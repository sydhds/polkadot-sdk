// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::{
	ExecError, InstantiateError, MemoryError, MemoryT, SharedState, SyscallHandler, VirtT,
};
use polkavm::{
	Caller, CallerRef, Config, Engine, ExecutionConfig, ExecutionError, Gas, GasMeteringKind,
	Instance, Linker, Module, ModuleConfig, Reg, Trap,
};
use std::{
	cell::RefCell,
	mem,
	rc::{Rc, Weak},
	sync::OnceLock,
};

static ENGINE: OnceLock<Engine> = OnceLock::new();

pub struct Virt {
	instance: Instance<Self>,
	memory: Rc<RefCell<Memory>>,
	exec_data: Option<ExecData>,
}

struct ExecData {
	/// `SyscallHandler<T>`
	syscall_handler: ErasedSyscallHandler,
	/// Option<*mut SharedState<T>>
	shared_state: usize,
}

pub enum Memory {
	Idle(Instance<Virt>),
	Executing(CallerRef<Virt>),
}

impl Memory {
	fn into_instance(self) -> Option<Instance<Virt>> {
		match self {
			Self::Idle(instance) => Some(instance),
			_ => None,
		}
	}

	fn into_caller(self) -> Option<CallerRef<Virt>> {
		match self {
			Self::Executing(caller) => Some(caller),
			_ => None,
		}
	}
}

type ErasedSyscallHandler = extern "C" fn(
	// &mut SharedState<T>
	state: usize,
	syscall_no: u32,
	a0: u32,
	a1: u32,
	a2: u32,
	a3: u32,
	a4: u32,
	a5: u32,
) -> u64;

fn engine() -> &'static Engine {
	ENGINE.get_or_init(|| {
		let config = Config::new();
		Engine::new(&config).expect("Default config is always valid; qed")
	})
}

impl VirtT for Virt {
	type Memory = Weak<RefCell<Memory>>;

	fn instantiate(program: &[u8]) -> Result<Self, InstantiateError> {
		let engine = engine();

		let mut module_config = ModuleConfig::new();
		module_config.set_gas_metering(Some(GasMeteringKind::Async));
		let module = Module::new(&engine, &module_config, program).map_err(|err| {
			log::error!("Failed to compile program: {}", err);
			InstantiateError::InvalidImage
		})?;

		let mut linker = Linker::new(&engine);
		linker.func_fallback(on_ecall);
		let instance = linker.instantiate_pre(&module).map_err(|err| {
			log::error!("Failed to link program: {err}");
			InstantiateError::InvalidImage
		})?;

		let instance = instance.instantiate().map_err(|err| {
			log::error!("Failed to instantiate program: {err}");
			InstantiateError::InvalidImage
		})?;
		let virt = Self {
			exec_data: None,
			memory: Rc::new(RefCell::new(Memory::Idle(instance.clone()))),
			instance,
		};
		Ok(virt)
	}

	fn execute<T>(
		&mut self,
		function: &str,
		syscall_handler: SyscallHandler<T>,
		shared_state: &mut SharedState<T>,
	) -> Result<(), ExecError> {
		self.internal_execute(function, syscall_handler, shared_state)
	}

	fn execute_and_destroy<T>(
		mut self,
		function: &str,
		syscall_handler: SyscallHandler<T>,
		shared_state: &mut SharedState<T>,
	) -> Result<(), ExecError> {
		self.internal_execute(function, syscall_handler, shared_state)
	}

	fn memory(&self) -> Self::Memory {
		Rc::downgrade(&self.memory)
	}
}

impl MemoryT for Weak<RefCell<Memory>> {
	fn read(&self, offset: u32, dest: &mut [u8]) -> Result<(), MemoryError> {
		let rc = self.upgrade().ok_or(MemoryError::InvalidInstance)?;
		let result = match &*rc.borrow() {
			Memory::Idle(instance) => instance.read_memory_into_slice(offset, dest),
			Memory::Executing(caller) => caller.read_memory_into_slice(offset, dest),
		};
		result.map(|_| ()).map_err(|_| MemoryError::OutOfBounds)
	}

	fn write(&mut self, offset: u32, src: &[u8]) -> Result<(), MemoryError> {
		let rc = self.upgrade().ok_or(MemoryError::InvalidInstance)?;
		let result = match &mut *rc.borrow_mut() {
			Memory::Idle(instance) => instance.write_memory(offset, src),
			Memory::Executing(caller) => caller.write_memory(offset, src),
		};
		result.map_err(|_| MemoryError::OutOfBounds)
	}
}

impl Virt {
	fn shared_state(&self) -> &SharedState<()> {
		unsafe { &*(self.exec_data.as_ref().unwrap().shared_state as *const _) }
	}

	fn shared_state_mut(&mut self) -> &mut SharedState<()> {
		unsafe { &mut *(self.exec_data.as_mut().unwrap().shared_state as *mut _) }
	}

	fn internal_execute<T>(
		&mut self,
		function: &str,
		syscall_handler: SyscallHandler<T>,
		shared_state: &mut SharedState<T>,
	) -> Result<(), ExecError> {
		let func = match self.instance.get_typed_func::<(), ()>(function) {
			Ok(func) => func,
			Err(err) => {
				log::error!("Failed to find exported function: {}", err);
				return Err(ExecError::InvalidImage);
			},
		};

		self.exec_data = Some(ExecData {
			syscall_handler: unsafe { mem::transmute(syscall_handler) },
			shared_state: shared_state as *mut _ as usize,
		});

		let mut execute_config = ExecutionConfig::default();
		execute_config.set_gas(Gas::MAX);
		let outcome = match func.call_ex(self, (), execute_config) {
			Ok(_) => Ok(()),
			Err(ExecutionError::Trap(_)) => Err(ExecError::Trap),
			Err(ExecutionError::OutOfGas) => Err(ExecError::OutOfGas),
			Err(err) => {
				log::error!("polkavm execution error: {}", err);
				Err(ExecError::Trap)
			},
		};

		self.exec_data = None;

		outcome
	}
}

fn on_ecall(mut caller: Caller<'_, Virt>, syscall_no: u32) -> Result<(), Trap> {
	let a0 = caller.get_reg(Reg::A0);
	let a1 = caller.get_reg(Reg::A1);
	let a2 = caller.get_reg(Reg::A2);
	let a3 = caller.get_reg(Reg::A3);
	let a4 = caller.get_reg(Reg::A4);
	let a5 = caller.get_reg(Reg::A5);

	// We need to access `caller` and its data at the same time. However, since the data
	// is behind a function the borrow checker can't make sure we don't access this field
	// twice. This doesn't change the type. It just splits the life times.
	//
	// # SAFETY
	//
	// We do not make any other call to `data_mut()` or `data()` and hence
	// do not create another reference to this data. This also assumes that other functions
	// of `Caller` do not access the data.
	let virt: &mut Virt = unsafe { &mut *(caller.data_mut() as *mut _) };

	// sync polkavm gas counter into host
	let gas_left_before = caller.gas_remaining().expect("metering is enabled; qed").get();
	virt.shared_state_mut().gas_left = gas_left_before;

	// needed for reading and writing memory from the syscall handler
	let instance =
		mem::replace(&mut *virt.memory.borrow_mut(), Memory::Executing(caller.into_ref()))
			.into_instance()
			.unwrap();

	let exec_data = virt
		.exec_data
		.as_ref()
		.expect("Data is set while executing. `on_ecall` is only called whole executing; qed");

	let result =
		(exec_data.syscall_handler)(exec_data.shared_state, syscall_no, a0, a1, a2, a3, a4, a5);

	let mut caller = mem::replace(&mut *virt.memory.borrow_mut(), Memory::Idle(instance))
		.into_caller()
		.unwrap();

	// sync host gas counter into polkavm
	let shared_state = virt.shared_state();
	let consume = gas_left_before.saturating_sub(shared_state.gas_left);
	caller.consume_gas(consume);

	if shared_state.exit {
		Err(Trap::default())
	} else {
		caller.set_reg(Reg::A0, result as u32);
		caller.set_reg(Reg::A1, (result >> 32) as u32);
		Ok(())
	}
}
