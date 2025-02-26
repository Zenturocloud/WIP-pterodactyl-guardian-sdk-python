"""
Code parsers for various languages.

This module provides parsers that extract code structure information
for different programming languages.
"""

import logging
import re
import ast
import json
from typing import Dict, List, Any, Optional, Union, Set, Tuple
from dataclasses import dataclass, field
import tempfile
import os
import subprocess

from ..exceptions import ParserError


@dataclass
class ParsedCode:
    """Parsed code information."""
    
    language: str
    source: str
    functions: List[Dict[str, Any]] = field(default_factory=list)
    variables: List[Dict[str, Any]] = field(default_factory=list)
    classes: List[Dict[str, Any]] = field(default_factory=list)
    imports: List[Dict[str, Any]] = field(default_factory=list)
    expressions: List[Dict[str, Any]] = field(default_factory=list)
    loops: List[Dict[str, Any]] = field(default_factory=list)
    conditions: List[Dict[str, Any]] = field(default_factory=list)
    exceptions: List[Dict[str, Any]] = field(default_factory=list)
    function_calls: List[Dict[str, Any]] = field(default_factory=list)
    info: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "language": self.language,
            "functions": self.functions,
            "variables": self.variables,
            "classes": self.classes,
            "imports": self.imports,
            "expressions": self.expressions,
            "loops": self.loops,
            "conditions": self.conditions,
            "exceptions": self.exceptions,
            "function_calls": self.function_calls,
            "info": self.info
        }


class CodeParser:
    """
    Parser for extracting code structure information.
    """
    
    def __init__(self, language: str, logger: Optional[logging.Logger] = None):
        """
        Initialize the code parser.
        
        Args:
            language: Code language
            logger: Logger instance
        """
        self.language = language.lower()
        self.logger = logger or logging.getLogger(__name__)
    
    def parse(self, source: str) -> ParsedCode:
        """
        Parse code and extract structure information.
        
        Args:
            source: Source code
            
        Returns:
            Parsed code information
            
        Raises:
            ParserError: If parsing fails
        """
        try:
            if self.language == "python":
                return self._parse_python(source)
            elif self.language in ["javascript", "typescript", "react"]:
                return self._parse_javascript(source)
            elif self.language == "php":
                return self._parse_php(source)
            else:
                
                return self._parse_generic(source)
                
        except Exception as e:
            self.logger.error(f"Error parsing {self.language} code: {e}")
            raise ParserError(f"Failed to parse {self.language} code: {e}")
    
    def _parse_python(self, source: str) -> ParsedCode:
        """
        Parse Python code.
        
        Args:
            source: Python source code
            
        Returns:
            Parsed code information
        """
        
        result = ParsedCode(language="python", source=source)
        
        try:
            
            tree = ast.parse(source)
            
           
            result.info = {
                "num_functions": len([n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]),
                "num_classes": len([n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]),
                "num_imports": len([n for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))]),
                "lines": source.count("\n") + 1
            }
            
          
            self._process_python_ast(tree, result)
            
            return result
            
        except SyntaxError as e:
            
            return self._parse_generic(source)
    
    def _process_python_ast(self, tree: ast.AST, result: ParsedCode) -> None:
        """
        Process Python AST nodes.
        
        Args:
            tree: Python AST
            result: Parsed code result to update
        """
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for name in node.names:
                    result.imports.append({
                        "name": name.name,
                        "alias": name.asname,
                        "line": node.lineno
                    })
            elif isinstance(node, ast.ImportFrom):
                for name in node.names:
                    result.imports.append({
                        "name": f"{node.module}.{name.name}" if node.module else name.name,
                        "alias": name.asname,
                        "line": node.lineno
                    })
        
       
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                args = []
                for arg in node.args.args:
                    if hasattr(arg, 'arg'):
                        args.append(arg.arg)
                    else:
                        args.append(str(arg))
                
                func = {
                    "name": node.name,
                    "line": node.lineno,
                    "args": args,
                    "body_size": len(node.body)
                }
                
                
                if hasattr(node, 'decorator_list') and node.decorator_list:
                    func["decorators"] = [
                        self._get_decorator_name(d) for d in node.decorator_list
                    ]
                
                result.functions.append(func)
        
        
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                bases = []
                for base in node.bases:
                    if isinstance(base, ast.Name):
                        bases.append(base.id)
                
                cls = {
                    "name": node.name,
                    "line": node.lineno,
                    "bases": bases,
                    "methods": []
                }
                
               
                for child in ast.iter_child_nodes(node):
                    if isinstance(child, ast.FunctionDef):
                        args = []
                        for arg in child.args.args:
                            if hasattr(arg, 'arg'):
                                args.append(arg.arg)
                            else:
                                args.append(str(arg))
                        
                        cls["methods"].append({
                            "name": child.name,
                            "line": child.lineno,
                            "args": args
                        })
                
                result.classes.append(cls)
        
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        value = None
                        if isinstance(node.value, ast.Constant):
                            value = node.value.value
                        elif isinstance(node.value, ast.Str):
                            value = node.value.s
                        elif isinstance(node.value, ast.Num):
                            value = node.value.n
                        elif isinstance(node.value, ast.List):
                            value = "list"
                        elif isinstance(node.value, ast.Dict):
                            value = "dict"
                        elif isinstance(node.value, ast.Set):
                            value = "set"
                        elif isinstance(node.value, ast.Tuple):
                            value = "tuple"
                        elif isinstance(node.value, ast.Call):
                            value = f"call({self._get_call_name(node.value)})"
                        
                        result.variables.append({
                            "name": target.id,
                            "line": node.lineno,
                            "value": value
                        })
        
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Expr):
                if isinstance(node.value, ast.Call):
                    call_name = self._get_call_name(node.value)
                    
                    
                    args = []
                    for arg in node.value.args:
                        if isinstance(arg, ast.Constant):
                            args.append(arg.value)
                        elif isinstance(arg, ast.Str):
                            args.append(arg.s)
                        elif isinstance(arg, ast.Name):
                            args.append(arg.id)
                        else:
                            args.append(type(arg).__name__)
                    
                    targets = []
                    if hasattr(node.value, 'func') and isinstance(node.value.func, ast.Attribute):
                        if hasattr(node.value.func, 'value') and isinstance(node.value.func.value, ast.Name):
                            targets.append(node.value.func.value.id)
                    
                    result.function_calls.append({
                        "name": call_name,
                        "line": node.lineno,
                        "args": args,
                        "targets": targets
                    })
                    
                   
                    result.expressions.append({
                        "type": "call_expression",
                        "name": call_name,
                        "line": node.lineno
                    })
                    
                elif isinstance(node.value, ast.BinOp):
                    op_type = type(node.value.op).__name__
                    left_value = None
                    right_value = None
                    
                    if isinstance(node.value.left, ast.Constant):
                        left_value = node.value.left.value
                    elif isinstance(node.value.left, ast.Str):
                        left_value = node.value.left.s
                    elif isinstance(node.value.left, ast.Name):
                        left_value = node.value.left.id
                    
                    if isinstance(node.value.right, ast.Constant):
                        right_value = node.value.right.value
                    elif isinstance(node.value.right, ast.Str):
                        right_value = node.value.right.s
                    elif isinstance(node.value.right, ast.Name):
                        right_value = node.value.right.id
                    
                    result.expressions.append({
                        "type": "binary_operation",
                        "operator": op_type,
                        "line": node.lineno,
                        "left": {
                            "type": type(node.value.left).__name__.lower(),
                            "value": left_value
                        },
                        "right": {
                            "type": type(node.value.right).__name__.lower(),
                            "value": right_value
                        }
                    })
        
        
        for node in ast.walk(tree):
            
            if isinstance(node, (ast.For, ast.While)):
                loop_type = "for" if isinstance(node, ast.For) else "while"
                loop = {
                    "type": loop_type,
                    "line": node.lineno,
                    "calls": []
                }
                
               
                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        call_name = self._get_call_name(child)
                        loop["calls"].append({
                            "name": call_name,
                            "line": getattr(child, "lineno", 0)
                        })
                
                result.loops.append(loop)
            
            
            if isinstance(node, ast.If):
                condition = {
                    "line": node.lineno,
                    "has_else": bool(node.orelse)
                }
                

                if_count = 0
                for child in ast.walk(node):
                    if isinstance(child, ast.If):
                        if_count += 1
                
                condition["nested_ifs"] = if_count - 1  
                
                result.conditions.append(condition)
            
            # Process exceptions
            if isinstance(node, ast.Try):
                exception = {
                    "line": node.lineno,
                    "handlers": len(node.handlers),
                    "has_finally": bool(node.finalbody),
                    "handler_body": any(len(handler.body) > 0 for handler in node.handlers)
                }
                
                result.exceptions.append(exception)
    
    def _get_call_name(self, node: ast.Call) -> str:
        """
        Get the name of a function call.
        
        Args:
            node: Call node
            
        Returns:
            Function call name
        """
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
            elif isinstance(node.func.value, ast.Attribute):
                parent = self._get_call_name(ast.Call(func=node.func.value))
                return f"{parent}.{node.func.attr}"
            return node.func.attr
        return "unknown"
    
    def _get_decorator_name(self, node: ast.expr) -> str:
        """
        Get the name of a decorator.
        
        Args:
            node: Decorator node
            
        Returns:
            Decorator name
        """
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Call):
            return self._get_call_name(node)
        elif isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                return f"{node.value.id}.{node.attr}"
        return "unknown"
    
    def _parse_javascript(self, source: str) -> ParsedCode:
        """
        Parse JavaScript/TypeScript code.
        
        Args:
            source: JavaScript source code
            
        Returns:
            Parsed code information
        """
        result = self._parse_generic(source)
        result.language = "javascript"
        return result
    
    def _parse_php(self, source: str) -> ParsedCode:
        """
        Parse PHP code.
        
        Args:
            source: PHP source code
            
        Returns:
            Parsed code information
        """
        result = self._parse_generic(source)
        result.language = "php"
        return result
    
    def _parse_generic(self, source: str) -> ParsedCode:
        """
        Parse code using a generic approach.
        
        Args:
            source: Source code
            
        Returns:
            Parsed code information
        """
       
        result = ParsedCode(language=self.language, source=source)
        
        
        result.info = {
            "lines": source.count("\n") + 1,
            "size": len(source)
        }
        
        
        function_pattern = r'(?:function\s+(\w+)|(\w+)\s*=\s*function|\b(class)\s+(\w+))'
        for match in re.finditer(function_pattern, source):
            func_name = match.group(1) or match.group(2) or match.group(4)
            if match.group(3) == "class":
                
                result.classes.append({
                    "name": func_name,
                    "line": source[:match.start()].count("\n") + 1
                })
            else:
                
                result.functions.append({
                    "name": func_name,
                    "line": source[:match.start()].count("\n") + 1
                })
        
       
        import_pattern = r'(?:import|require|include|use|from)\s+[\w\s,.{}\'"]+?[;\n]'
        for match in re.finditer(import_pattern, source):
            result.imports.append({
                "name": match.group(0).strip(),
                "line": source[:match.start()].count("\n") + 1
            })
        
       
        var_pattern = r'(?:var|let|const|public|private|protected|my|our|\$|self\.)\s*(\w+)\s*=\s*([^;]+)'
        for match in re.finditer(var_pattern, source):
            var_name = match.group(1)
            var_value = match.group(2).strip()
            result.variables.append({
                "name": var_name,
                "line": source[:match.start()].count("\n") + 1,
                "value": var_value[:100] if len(var_value) > 100 else var_value  
            })
        
      
        call_pattern = r'(\w+(?:\.\w+)*)\s*\(([^)]*)\)'
        for match in re.finditer(call_pattern, source):
            func_name = match.group(1)
            args = match.group(2).strip()
            
            
            prev_chars = source[max(0, match.start() - 20):match.start()]
            if re.search(r'function|class|def|\bfunction\b|\bclass\b|\bdef\b', prev_chars):
                continue
            
            result.function_calls.append({
                "name": func_name,
                "line": source[:match.start()].count("\n") + 1,
                "args": args.split(",") if args else []
            })
        
        
        loop_pattern = r'\b(for|while|foreach|do)\b'
        for match in re.finditer(loop_pattern, source):
            result.loops.append({
                "type": match.group(1),
                "line": source[:match.start()].count("\n") + 1
            })
        
        
        condition_pattern = r'\b(if|switch|case|else if|elif)\b'
        for match in re.finditer(condition_pattern, source):
            result.conditions.append({
                "type": match.group(1),
                "line": source[:match.start()].count("\n") + 1
            })
        
       
        exception_pattern = r'\b(try|catch|except|finally|rescue)\b'
        for match in re.finditer(exception_pattern, source):
            result.exceptions.append({
                "type": match.group(1),
                "line": source[:match.start()].count("\n") + 1
            })
        
        return result
