use crate::ast::*;
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum ParseError {
    #[error("Unexpected end of input")]
    UnexpectedEof,
    #[error("Unexpected token: '{found}', expected: '{expected}'")]
    UnexpectedToken { expected: String, found: String },
    #[error("Syntax error: {0}")]
    SyntaxError(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Keyword(String),
    Ident(String),
    Number(String),
    StringLiteral(String),
    Comma,
    Dot,
    Semicolon,
    LParen,
    RParen,
    Equal,
    NotEqual,
    GreaterThan,
    GreaterEqual,
    LessThan,
    LessEqual,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
}

pub struct Lexer<'a> {
    input: &'a str,
    chars: std::iter::Peekable<std::str::CharIndices<'a>>,
}

impl<'a> Lexer<'a> {
    pub fn new(input: &'a str) -> Self {
        Self {
            input,
            chars: input.char_indices().peekable(),
        }
    }

    pub fn tokenize(&mut self) -> Result<Vec<Token>, ParseError> {
        let mut tokens = Vec::new();
        while let Some(&(i, ch)) = self.chars.peek() {
            if ch.is_whitespace() {
                self.chars.next();
                continue;
            }
            if ch == '-' {
                let mut lookahead = self.chars.clone();
                lookahead.next();
                if let Some((_, '-')) = lookahead.peek() {
                    // SQL comment, skip line
                    while let Some((_, c)) = self.chars.next() {
                        if c == '\n' {
                            break;
                        }
                    }
                    continue;
                }
            }

            match ch {
                ',' => { self.chars.next(); tokens.push(Token::Comma); }
                '.' => { self.chars.next(); tokens.push(Token::Dot); }
                ';' => { self.chars.next(); tokens.push(Token::Semicolon); }
                '(' => { self.chars.next(); tokens.push(Token::LParen); }
                ')' => { self.chars.next(); tokens.push(Token::RParen); }
                '+' => { self.chars.next(); tokens.push(Token::Plus); }
                '-' => { self.chars.next(); tokens.push(Token::Minus); }
                '*' => { self.chars.next(); tokens.push(Token::Star); }
                '/' => { self.chars.next(); tokens.push(Token::Slash); }
                '%' => { self.chars.next(); tokens.push(Token::Percent); }
                '=' => { self.chars.next(); tokens.push(Token::Equal); }
                '!' => {
                    self.chars.next();
                    if let Some((_, '=')) = self.chars.peek() {
                        self.chars.next();
                        tokens.push(Token::NotEqual);
                    } else {
                        return Err(ParseError::SyntaxError("Unexpected '!' character".into()));
                    }
                }
                '<' => {
                    self.chars.next();
                    if let Some((_, '=')) = self.chars.peek() {
                        self.chars.next();
                        tokens.push(Token::LessEqual);
                    } else if let Some((_, '>')) = self.chars.peek() {
                        self.chars.next();
                        tokens.push(Token::NotEqual);
                    } else {
                        tokens.push(Token::LessThan);
                    }
                }
                '>' => {
                    self.chars.next();
                    if let Some((_, '=')) = self.chars.peek() {
                        self.chars.next();
                        tokens.push(Token::GreaterEqual);
                    } else {
                        tokens.push(Token::GreaterThan);
                    }
                }
                '\'' => {
                    self.chars.next();
                    let mut s = String::new();
                    let mut closed = false;
                    while let Some((_, c)) = self.chars.next() {
                        if c == '\'' {
                            if let Some((_, '\'')) = self.chars.peek() {
                                self.chars.next();
                                s.push('\'');
                            } else {
                                closed = true;
                                break;
                            }
                        } else {
                            s.push(c);
                        }
                    }
                    if !closed {
                        return Err(ParseError::SyntaxError("Unterminated string literal".into()));
                    }
                    tokens.push(Token::StringLiteral(s));
                }
                '0'..='9' => {
                    let mut num = String::new();
                    while let Some(&(_, c)) = self.chars.peek() {
                        if c.is_ascii_digit() || c == '.' {
                            num.push(c);
                            self.chars.next();
                        } else {
                            break;
                        }
                    }
                    tokens.push(Token::Number(num));
                }
                'a'..='z' | 'A'..='Z' | '_' => {
                    let mut ident = String::new();
                    while let Some(&(_, c)) = self.chars.peek() {
                        if c.is_alphanumeric() || c == '_' {
                            ident.push(c);
                            self.chars.next();
                        } else {
                            break;
                        }
                    }
                    let upper = ident.to_uppercase();
                    match upper.as_str() {
                        "SELECT" | "FROM" | "WHERE" | "JOIN" | "INNER" | "LEFT" | "RIGHT" | "FULL" |
                        "ON" | "GROUP" | "BY" | "HAVING" | "ORDER" | "ASC" | "DESC" | "LIMIT" |
                        "OFFSET" | "INSERT" | "INTO" | "VALUES" | "UPDATE" | "SET" | "DELETE" |
                        "AND" | "OR" | "NOT" | "IN" | "IS" | "NULL" | "TRUE" | "FALSE" | "AS" |
                        "DISTINCT" | "WITH" | "BEGIN" | "COMMIT" | "ROLLBACK" | "SAVEPOINT" => {
                            tokens.push(Token::Keyword(upper));
                        }
                        _ => {
                            tokens.push(Token::Ident(ident));
                        }
                    }
                }
                _ => {
                    return Err(ParseError::SyntaxError(format!("Unexpected character: {}", ch)));
                }
            }
        }
        Ok(tokens)
    }
}

pub struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    pub fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn next_token(&mut self) -> Option<Token> {
        if self.pos < self.tokens.len() {
            let tok = self.tokens[self.pos].clone();
            self.pos += 1;
            Some(tok)
        } else {
            None
        }
    }

    fn match_keyword(&mut self, kw: &str) -> bool {
        if let Some(Token::Keyword(k)) = self.peek() {
            if k == kw {
                self.pos += 1;
                return true;
            }
        }
        false
    }

    fn expect_keyword(&mut self, kw: &str) -> Result<(), ParseError> {
        if self.match_keyword(kw) {
            Ok(())
        } else {
            Err(ParseError::UnexpectedToken {
                expected: kw.to_string(),
                found: format!("{:?}", self.peek()),
            })
        }
    }

    pub fn parse_statement(&mut self) -> Result<SqlStatement, ParseError> {
        if self.match_keyword("SELECT") || self.match_keyword("WITH") {
            self.pos -= 1;
            let sel = self.parse_select()?;
            Ok(SqlStatement::Select(sel))
        } else if self.match_keyword("INSERT") {
            let ins = self.parse_insert()?;
            Ok(SqlStatement::Insert(ins))
        } else if self.match_keyword("UPDATE") {
            let upd = self.parse_update()?;
            Ok(SqlStatement::Update(upd))
        } else if self.match_keyword("DELETE") {
            let del = self.parse_delete()?;
            Ok(SqlStatement::Delete(del))
        } else if self.match_keyword("BEGIN") {
            Ok(SqlStatement::Begin)
        } else if self.match_keyword("COMMIT") {
            Ok(SqlStatement::Commit)
        } else if self.match_keyword("ROLLBACK") {
            if self.match_keyword("TO") {
                if let Some(Token::Ident(sp)) = self.next_token() {
                    Ok(SqlStatement::RollbackTo(sp))
                } else {
                    Err(ParseError::SyntaxError("Expected savepoint name after ROLLBACK TO".into()))
                }
            } else {
                Ok(SqlStatement::Rollback)
            }
        } else if self.match_keyword("SAVEPOINT") {
            if let Some(Token::Ident(sp)) = self.next_token() {
                Ok(SqlStatement::Savepoint(sp))
            } else {
                Err(ParseError::SyntaxError("Expected savepoint identifier".into()))
            }
        } else {
            Err(ParseError::SyntaxError(format!("Unsupported statement starting at {:?}", self.peek())))
        }
    }

    pub fn parse_select(&mut self) -> Result<SelectStatement, ParseError> {
        let mut ctes = Vec::new();
        if self.match_keyword("WITH") {
            loop {
                let name = match self.next_token() {
                    Some(Token::Ident(id)) => id,
                    other => return Err(ParseError::SyntaxError(format!("Expected CTE name, got {:?}", other))),
                };
                self.expect_keyword("AS")?;
                if self.next_token() != Some(Token::LParen) {
                    return Err(ParseError::SyntaxError("Expected '(' after CTE AS".into()));
                }
                let query = self.parse_select()?;
                if self.next_token() != Some(Token::RParen) {
                    return Err(ParseError::SyntaxError("Expected ')' closing CTE query".into()));
                }
                ctes.push(CommonTableExpression {
                    name,
                    columns: Vec::new(),
                    query,
                });
                if let Some(Token::Comma) = self.peek() {
                    self.next_token();
                } else {
                    break;
                }
            }
        }

        self.expect_keyword("SELECT")?;
        let distinct = self.match_keyword("DISTINCT");

        let mut projection = Vec::new();
        loop {
            let expr = self.parse_expression(0)?;
            let alias = if self.match_keyword("AS") {
                match self.next_token() {
                    Some(Token::Ident(id)) => Some(id),
                    _ => return Err(ParseError::SyntaxError("Expected alias after AS".into())),
                }
            } else if let Some(Token::Ident(id)) = self.peek() {
                let id = id.clone();
                self.next_token();
                Some(id)
            } else {
                None
            };
            projection.push(SelectItem { expr, alias });

            if let Some(Token::Comma) = self.peek() {
                self.next_token();
            } else {
                break;
            }
        }

        let mut from = None;
        let mut joins = Vec::new();
        if self.match_keyword("FROM") {
            let tbl_name = match self.next_token() {
                Some(Token::Ident(n)) => n,
                other => return Err(ParseError::SyntaxError(format!("Expected table name in FROM, got {:?}", other))),
            };
            let alias = if self.match_keyword("AS") {
                match self.next_token() {
                    Some(Token::Ident(a)) => Some(a),
                    _ => None,
                }
            } else if let Some(Token::Ident(a)) = self.peek() {
                let a = a.clone();
                self.next_token();
                Some(a)
            } else {
                None
            };
            from = Some(TableRef { name: tbl_name, alias });

            while self.match_keyword("JOIN") || self.match_keyword("INNER") || self.match_keyword("LEFT") {
                // handle join parsing
                let join_type = JoinType::Inner;
                let join_table = match self.next_token() {
                    Some(Token::Ident(n)) => TableRef { name: n, alias: None },
                    _ => return Err(ParseError::SyntaxError("Expected joined table name".into())),
                };
                let on_cond = if self.match_keyword("ON") {
                    Some(self.parse_expression(0)?)
                } else {
                    None
                };
                joins.push(JoinClause {
                    join_type,
                    table: join_table,
                    on_condition: on_cond,
                });
            }
        }

        let where_clause = if self.match_keyword("WHERE") {
            Some(self.parse_expression(0)?)
        } else {
            None
        };

        let mut group_by = Vec::new();
        if self.match_keyword("GROUP") {
            self.expect_keyword("BY")?;
            loop {
                group_by.push(self.parse_expression(0)?);
                if let Some(Token::Comma) = self.peek() {
                    self.next_token();
                } else {
                    break;
                }
            }
        }

        let having = if self.match_keyword("HAVING") {
            Some(self.parse_expression(0)?)
        } else {
            None
        };

        let mut order_by = Vec::new();
        if self.match_keyword("ORDER") {
            self.expect_keyword("BY")?;
            loop {
                let expr = self.parse_expression(0)?;
                let direction = if self.match_keyword("DESC") {
                    OrderDirection::Desc
                } else {
                    self.match_keyword("ASC");
                    OrderDirection::Asc
                };
                order_by.push(OrderByExpr {
                    expr,
                    direction,
                    nulls_first: false,
                });
                if let Some(Token::Comma) = self.peek() {
                    self.next_token();
                } else {
                    break;
                }
            }
        }

        let limit = if self.match_keyword("LIMIT") {
            match self.next_token() {
                Some(Token::Number(n)) => n.parse::<usize>().ok(),
                _ => None,
            }
        } else {
            None
        };

        let offset = if self.match_keyword("OFFSET") {
            match self.next_token() {
                Some(Token::Number(n)) => n.parse::<usize>().ok(),
                _ => None,
            }
        } else {
            None
        };

        Ok(SelectStatement {
            ctes,
            distinct,
            projection,
            from,
            joins,
            where_clause,
            group_by,
            having,
            order_by,
            limit,
            offset,
        })
    }

    fn parse_insert(&mut self) -> Result<InsertStatement, ParseError> {
        self.expect_keyword("INTO")?;
        let table = match self.next_token() {
            Some(Token::Ident(t)) => t,
            _ => return Err(ParseError::SyntaxError("Expected table name in INSERT INTO".into())),
        };

        let mut columns = Vec::new();
        if let Some(Token::LParen) = self.peek() {
            self.next_token();
            loop {
                match self.next_token() {
                    Some(Token::Ident(c)) => columns.push(c),
                    other => return Err(ParseError::SyntaxError(format!("Expected column name, got {:?}", other))),
                }
                if let Some(Token::Comma) = self.peek() {
                    self.next_token();
                } else {
                    break;
                }
            }
            if self.next_token() != Some(Token::RParen) {
                return Err(ParseError::SyntaxError("Expected ')' closing column list".into()));
            }
        }

        self.expect_keyword("VALUES")?;
        let mut values = Vec::new();
        loop {
            if self.next_token() != Some(Token::LParen) {
                return Err(ParseError::SyntaxError("Expected '(' starting row values".into()));
            }
            let mut row = Vec::new();
            loop {
                row.push(self.parse_expression(0)?);
                if let Some(Token::Comma) = self.peek() {
                    self.next_token();
                } else {
                    break;
                }
            }
            if self.next_token() != Some(Token::RParen) {
                return Err(ParseError::SyntaxError("Expected ')' ending row values".into()));
            }
            values.push(row);
            if let Some(Token::Comma) = self.peek() {
                self.next_token();
            } else {
                break;
            }
        }

        Ok(InsertStatement {
            table,
            columns,
            values,
            returning: Vec::new(),
        })
    }

    fn parse_update(&mut self) -> Result<UpdateStatement, ParseError> {
        let table = match self.next_token() {
            Some(Token::Ident(t)) => t,
            _ => return Err(ParseError::SyntaxError("Expected table name in UPDATE".into())),
        };
        self.expect_keyword("SET")?;
        let mut assignments = Vec::new();
        loop {
            let col = match self.next_token() {
                Some(Token::Ident(c)) => c,
                _ => return Err(ParseError::SyntaxError("Expected column in SET clause".into())),
            };
            if self.next_token() != Some(Token::Equal) {
                return Err(ParseError::SyntaxError("Expected '=' in SET assignment".into()));
            }
            let expr = self.parse_expression(0)?;
            assignments.push((col, expr));
            if let Some(Token::Comma) = self.peek() {
                self.next_token();
            } else {
                break;
            }
        }

        let where_clause = if self.match_keyword("WHERE") {
            Some(self.parse_expression(0)?)
        } else {
            None
        };

        Ok(UpdateStatement {
            table,
            assignments,
            where_clause,
            returning: Vec::new(),
        })
    }

    fn parse_delete(&mut self) -> Result<DeleteStatement, ParseError> {
        self.expect_keyword("FROM")?;
        let table = match self.next_token() {
            Some(Token::Ident(t)) => t,
            _ => return Err(ParseError::SyntaxError("Expected table name in DELETE FROM".into())),
        };

        let where_clause = if self.match_keyword("WHERE") {
            Some(self.parse_expression(0)?)
        } else {
            None
        };

        Ok(DeleteStatement {
            table,
            where_clause,
            returning: Vec::new(),
        })
    }

    fn parse_expression(&mut self, min_prec: u8) -> Result<Expression, ParseError> {
        let mut left = self.parse_primary()?;

        while let Some(op) = self.peek_binary_op() {
            let prec = Self::operator_precedence(&op);
            if prec < min_prec {
                break;
            }
            self.next_token(); // consume operator
            let right = self.parse_expression(prec + 1)?;
            left = Expression::BinaryOp {
                left: Box::new(left),
                op,
                right: Box::new(right),
            };
        }

        Ok(left)
    }

    fn peek_binary_op(&self) -> Option<BinaryOperator> {
        match self.peek() {
            Some(Token::Equal) => Some(BinaryOperator::Eq),
            Some(Token::NotEqual) => Some(BinaryOperator::NotEq),
            Some(Token::GreaterThan) => Some(BinaryOperator::Gt),
            Some(Token::GreaterEqual) => Some(BinaryOperator::Gte),
            Some(Token::LessThan) => Some(BinaryOperator::Lt),
            Some(Token::LessEqual) => Some(BinaryOperator::Lte),
            Some(Token::Plus) => Some(BinaryOperator::Plus),
            Some(Token::Minus) => Some(BinaryOperator::Minus),
            Some(Token::Star) => Some(BinaryOperator::Multiply),
            Some(Token::Slash) => Some(BinaryOperator::Divide),
            Some(Token::Keyword(k)) if k == "AND" => Some(BinaryOperator::And),
            Some(Token::Keyword(k)) if k == "OR" => Some(BinaryOperator::Or),
            _ => None,
        }
    }

    fn operator_precedence(op: &BinaryOperator) -> u8 {
        match op {
            BinaryOperator::Or => 1,
            BinaryOperator::And => 2,
            BinaryOperator::Eq | BinaryOperator::NotEq |
            BinaryOperator::Gt | BinaryOperator::Gte |
            BinaryOperator::Lt | BinaryOperator::Lte => 3,
            BinaryOperator::Plus | BinaryOperator::Minus => 4,
            BinaryOperator::Multiply | BinaryOperator::Divide | BinaryOperator::Modulo => 5,
            _ => 0,
        }
    }

    fn parse_primary(&mut self) -> Result<Expression, ParseError> {
        match self.next_token() {
            Some(Token::Number(n)) => {
                if let Ok(i) = n.parse::<i64>() {
                    Ok(Expression::Literal(LiteralValue::Integer(i)))
                } else if let Ok(f) = n.parse::<f64>() {
                    Ok(Expression::Literal(LiteralValue::Float(f)))
                } else {
                    Err(ParseError::SyntaxError(format!("Invalid number literal: {}", n)))
                }
            }
            Some(Token::StringLiteral(s)) => Ok(Expression::Literal(LiteralValue::String(s))),
            Some(Token::Keyword(k)) if k == "TRUE" => Ok(Expression::Literal(LiteralValue::Boolean(true))),
            Some(Token::Keyword(k)) if k == "FALSE" => Ok(Expression::Literal(LiteralValue::Boolean(false))),
            Some(Token::Keyword(k)) if k == "NULL" => Ok(Expression::Literal(LiteralValue::Null)),
            Some(Token::Ident(name)) => {
                if let Some(Token::Dot) = self.peek() {
                    self.next_token();
                    if let Some(Token::Ident(col)) = self.next_token() {
                        Ok(Expression::QualifiedColumn { table: name, column: col })
                    } else {
                        Err(ParseError::SyntaxError("Expected column name after '.'".into()))
                    }
                } else if let Some(Token::LParen) = self.peek() {
                    self.next_token();
                    let mut args = Vec::new();
                    if self.peek() != Some(&Token::RParen) {
                        loop {
                            args.push(self.parse_expression(0)?);
                            if let Some(Token::Comma) = self.peek() {
                                self.next_token();
                            } else {
                                break;
                            }
                        }
                    }
                    if self.next_token() != Some(Token::RParen) {
                        return Err(ParseError::SyntaxError("Expected ')' closing function call".into()));
                    }
                    Ok(Expression::FunctionCall { name, args })
                } else {
                    Ok(Expression::Identifier(name))
                }
            }
            Some(Token::LParen) => {
                let expr = self.parse_expression(0)?;
                if self.next_token() != Some(Token::RParen) {
                    return Err(ParseError::SyntaxError("Expected ')' closing expression".into()));
                }
                Ok(expr)
            }
            other => Err(ParseError::SyntaxError(format!("Unexpected token in expression: {:?}", other))),
        }
    }
}
