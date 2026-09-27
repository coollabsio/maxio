#![allow(
    clippy::collapsible_if,
    clippy::redundant_closure,
    clippy::redundant_pattern_matching,
    clippy::needless_borrows_for_generic_args,
    clippy::io_other_error,
    clippy::if_same_then_else,
    clippy::manual_pattern_char_comparison,
    clippy::derivable_impls,
    clippy::items_after_test_module,
    clippy::overly_complex_bool_expr,
    clippy::too_many_arguments,
    clippy::new_without_default,
    clippy::needless_bool,
    clippy::collapsible_else_if
)]

pub mod api;
pub mod auth;
pub mod config;
pub mod embedded;
pub mod error;
pub mod openapi;
pub mod server;
pub mod storage;
pub mod xml;
