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

use derive_syn_parse::Parse;
use proc_macro2::{Span, TokenTree};
use quote::ToTokens;
use syn::{
	parse2,
	token::{Bracket, Paren},
	Expr, Ident, ImplItemFn, Item, LitInt, Result, Token,
};

#[cfg(test)]
macro_rules! assert_error_matches {
	($expr:expr, $reg:literal) => {
		match $expr {
			Ok(_) => panic!("Expected an `Error(..)`, but got Ok(..)"),
			Err(e) => {
				let error_message = e.to_string();
				let re = regex::Regex::new($reg).expect("Invalid regex pattern");
				assert!(
					re.is_match(&error_message),
					"Error message \"{}\" does not match the pattern \"{}\"",
					error_message,
					$reg
				);
			},
		}
	};
}

pub mod keywords {
	use syn::custom_keyword;

	custom_keyword!(tasks);
	custom_keyword!(task_list);
	custom_keyword!(task_condition);
	custom_keyword!(task_index);
	custom_keyword!(pallet);
}

pub struct TasksDef;

impl TasksDef {
	pub fn try_from(_span: Span, _index: usize, _item: &mut Item) -> Result<Self> {
		Ok(TasksDef {})
	}
}

pub struct TaskDef {
	task_attrs: Vec<TaskAttrType>,
	item: ImplItemFn,
}

impl syn::parse::Parse for TaskDef {
	fn parse(input: syn::parse::ParseStream) -> Result<Self> {
		let mut item = input.parse::<ImplItemFn>()?;
		// we only want to activate TaskAttrType parsing errors for tasks-related attributes,
		// so we filter them here
		let (task_attrs, normal_attrs) = item.attrs.into_iter().partition(|attr| {
			let mut path_tokens = attr.path().to_token_stream().into_iter();
			let (
				Some(TokenTree::Ident(prefix)),
				Some(TokenTree::Punct(_)),
				Some(TokenTree::Ident(suffix)),
			) = (path_tokens.next(), path_tokens.next(), path_tokens.next())
			else {
				return false
			};
			// N.B: the `PartialEq` impl between `Ident` and `&str` is more efficient than
			// parsing and makes no allocations
			prefix == "pallet" &&
				(suffix == "tasks" ||
					suffix == "task_list" ||
					suffix == "task_condition" ||
					suffix == "task_index")
		});
		item.attrs = normal_attrs;
		let task_attrs: Vec<TaskAttrType> = task_attrs
			.into_iter()
			.map(|attr| parse2::<TaskAttrType>(attr.to_token_stream()))
			.collect::<Result<_>>()?;

		Ok(TaskDef { task_attrs, item })
	}
}

#[derive(Parse, Debug)]
pub enum TaskAttrType {
	#[peek(keywords::task_list, name = "#[pallet::task_list(..)]")]
	TaskList {
		_tasks: keywords::task_list,
		#[paren]
		_paren: Paren,
		#[inside(_paren)]
		expr: Expr,
	},
	#[peek(keywords::task_index, name = "#[pallet::task_index(..)")]
	TaskIndex {
		_task_index: keywords::task_index,
		#[paren]
		_paren: Paren,
		#[inside(_paren)]
		index: LitInt,
	},
	#[peek(keywords::task_condition, name = "#[pallet::task_condition(..)")]
	TaskCondition {
		_condition: keywords::task_condition,
		#[paren]
		_paren: Paren,
		#[inside(_paren)]
		_pipe1: Token![|],
		#[inside(_paren)]
		_ident: Ident,
		#[inside(_paren)]
		_pipe2: Token![|],
		#[inside(_paren)]
		expr: Expr,
	},
	#[peek(keywords::tasks, name = "#[pallet::tasks]")]
	Tasks { _tasks: keywords::tasks },
}

#[derive(Parse, Debug)]
pub struct PalletTaskAttr {
	_pound: Token![#],
	#[bracket]
	_bracket: Bracket,
	#[inside(_bracket)]
	_pallet: keywords::pallet,
	#[inside(_bracket)]
	_colons: Token![::],
	#[inside(_bracket)]
	_attr: TaskAttrType,
}

#[cfg(test)]
use quote::quote;

#[test]
fn test_parse_pallet_task_list_() {
	parse2::<PalletTaskAttr>(quote!(#[pallet::task_list(Something::iter())])).unwrap();
	parse2::<PalletTaskAttr>(quote!(#[pallet::task_list(iter())])).unwrap();
	assert_error_matches!(
		parse2::<PalletTaskAttr>(quote!(#[pallet::task_list()])),
		"expected an expression"
	);
	assert_error_matches!(
		parse2::<PalletTaskAttr>(quote!(#[pallet::task_list])),
		"expected parentheses"
	);
}

#[test]
fn test_parse_pallet_task_index() {
	parse2::<PalletTaskAttr>(quote!(#[pallet::task_index(3)])).unwrap();
	parse2::<PalletTaskAttr>(quote!(#[pallet::task_index(0)])).unwrap();
	parse2::<PalletTaskAttr>(quote!(#[pallet::task_index(17)])).unwrap();
	assert_error_matches!(
		parse2::<PalletTaskAttr>(quote!(#[pallet::task_index])),
		"expected parentheses"
	);
	assert_error_matches!(
		parse2::<PalletTaskAttr>(quote!(#[pallet::task_index("hey")])),
		"expected integer literal"
	);
	assert_error_matches!(
		parse2::<PalletTaskAttr>(quote!(#[pallet::task_index(0.3)])),
		"expected integer literal"
	);
}

#[test]
fn test_parse_pallet_task_condition() {
	parse2::<PalletTaskAttr>(quote!(#[pallet::task_condition(|x| x.is_some())])).unwrap();
	parse2::<PalletTaskAttr>(quote!(#[pallet::task_condition(|_x| some_expr())])).unwrap();
	assert_error_matches!(
		parse2::<PalletTaskAttr>(quote!(#[pallet::task_condition(x.is_some())])),
		"expected `|`"
	);
	assert_error_matches!(
		parse2::<PalletTaskAttr>(quote!(#[pallet::task_condition(|| something())])),
		"expected identifier"
	);
}

#[test]
fn test_parse_pallet_tasks() {
	parse2::<PalletTaskAttr>(quote!(#[pallet::tasks])).unwrap();
	assert_error_matches!(parse2::<PalletTaskAttr>(quote!(#[pallet::taskss])), "expected one of");
	assert_error_matches!(parse2::<PalletTaskAttr>(quote!(#[pallet::tasks_])), "expected one of");
	assert_error_matches!(parse2::<PalletTaskAttr>(quote!(#[pallet::tasks()])), "unexpected token");
}
