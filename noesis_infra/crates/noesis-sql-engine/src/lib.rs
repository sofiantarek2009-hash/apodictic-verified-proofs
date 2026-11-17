pub mod ast;
pub mod parser;
pub mod evaluator;

pub use ast::*;
pub use parser::{Lexer, Parser, ParseError};
pub use evaluator::{ExpressionEvaluator, EvalValue};

pub fn parse_sql(sql: &str) -> Result<SqlStatement, ParseError> {
    let mut lexer = Lexer::new(sql);
    let tokens = lexer.tokenize()?;
    let mut parser = Parser::new(tokens);
    parser.parse_statement()
}
