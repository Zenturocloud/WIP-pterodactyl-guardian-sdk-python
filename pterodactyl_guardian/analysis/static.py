"""
Static code analysis for Pterodactyl Guardian SDK.

This module provides static code analysis functionality to understand
code structure and identify suspicious patterns.
"""

import logging
import re
import time
from typing import Dict, List, Any, Optional, Union, Set, Tuple
from enum import Enum, auto
import ast
import json

from ..enums import AnalysisLevel
from ..exceptions import AnalysisError, ParserError
from .parser import CodeParser, ParsedCode


class StaticAnalysis:
    """
    Static code analysis for detecting suspicious patterns.
    """
    
    def __init__(
        self,
        analysis_level: str = AnalysisLevel.STANDARD.value,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize the static analyzer.
        
        Args:
            analysis_level: Analysis level (basic, standard, deep)
            logger: Logger instance
        """
        self.analysis_level = analysis_level
        self.logger = logger or logging.getLogger(__name__)
        
        
        self.parsers: Dict[str, CodeParser] = {}
        
        
        self._cache: Dict[str, Dict[str, Any]] = {}
    
    def analyze(
        self,
        detection_result: Any,
        content: str,
        file_type: str = "text",
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Analyze code for suspicious patterns.
        
        Args:
            detection_result: Detection result to enhance
            content: Code content to analyze
            file_type: Type of file/content
            context: Additional context for analysis
            
        Returns:
            Enhanced detection result
        """
       
        if self.analysis_level == AnalysisLevel.BASIC.value or not self._is_code_file(file_type):
            return detection_result
        
        try:
           
            parsed = self._parse_code(content, file_type)
            
            
            if self.analysis_level == AnalysisLevel.STANDARD.value:
                self._perform_standard_analysis(detection_result, parsed, context)
            elif self.analysis_level == AnalysisLevel.DEEP.value:
                self._perform_deep_analysis(detection_result, parsed, context)
            
            return detection_result
            
        except Exception as e:
            self.logger.error(f"Error during static analysis: {e}")
            return detection_result
    
    def _is_code_file(self, file_type: str) -> bool:
        """
        Check if file type is code.
        
        Args:
            file_type: File type
            
        Returns:
            True if file is code, False otherwise
        """
        code_types = [
            "php", "javascript", "python", "ruby", "perl", "shell",
            "java", "c", "cpp", "csharp", "go", "rust", "typescript",
            "react"
        ]
        return file_type.lower() in code_types
    
    def _parse_code(self, content: str, file_type: str) -> ParsedCode:
        """
        Parse code using appropriate parser.
        
        Args:
            content: Code content
            file_type: File type
            
        Returns:
            Parsed code object
        """

        if file_type not in self.parsers:
            self.parsers[file_type] = CodeParser(file_type)
        
        parser = self.parsers[file_type]
        return parser.parse(content)
    
    def _perform_standard_analysis(
        self,
        detection_result: Any,
        parsed: ParsedCode,
        context: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Perform standard level analysis.
        
        Args:
            detection_result: Detection result to enhance
            parsed: Parsed code
            context: Additional context
        """
       
        if hasattr(detection_result, "code_info"):
            detection_result.code_info = parsed.info
        
      
        suspicious_funcs = self._find_suspicious_functions(parsed)
        if suspicious_funcs:
            if hasattr(detection_result, "suspicious_functions"):
                detection_result.suspicious_functions = suspicious_funcs
            
            
            if hasattr(detection_result, "score"):
                boost = min(len(suspicious_funcs) * 0.05, 0.2)
                detection_result.score = min(detection_result.score + boost, 1.0)
        
       
        suspicious_vars = self._find_suspicious_variables(parsed)
        if suspicious_vars:
            if hasattr(detection_result, "suspicious_variables"):
                detection_result.suspicious_variables = suspicious_vars
    
    def _perform_deep_analysis(
        self,
        detection_result: Any,
        parsed: ParsedCode,
        context: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Perform deep level analysis.
        
        Args:
            detection_result: Detection result to enhance
            parsed: Parsed code
            context: Additional context
        """
     
        self._perform_standard_analysis(detection_result, parsed, context)
        
     
        flow_issues = self._analyze_control_flow(parsed)
        if flow_issues and hasattr(detection_result, "flow_issues"):
            detection_result.flow_issues = flow_issues
        
       
        data_flow = self._analyze_data_flow(parsed)
        if data_flow and hasattr(detection_result, "data_flow"):
            detection_result.data_flow = data_flow
        
       
        behaviors = self._identify_behaviors(parsed)
        if behaviors and hasattr(detection_result, "behaviors"):
            detection_result.behaviors = behaviors
            
           
            if hasattr(detection_result, "score"):
                high_risk_behaviors = [b for b in behaviors if b.get("risk", "low") in ["high", "critical"]]
                boost = min(len(high_risk_behaviors) * 0.1, 0.3)
                detection_result.score = min(detection_result.score + boost, 1.0)
    
    def _find_suspicious_functions(self, parsed: ParsedCode) -> List[Dict[str, Any]]:
        """
        Find suspicious function calls.
        
        Args:
            parsed: Parsed code
            
        Returns:
            List of suspicious functions
        """
        suspicious = []
        high_risk_functions = {
            "php": [
                "eval", "exec", "shell_exec", "system", "passthru", "popen",
                "proc_open", "pcntl_exec", "assert", "create_function",
                "include", "include_once", "require", "require_once"
            ],
            "javascript": [
                "eval", "Function", "setTimeout", "setInterval",
                "document.write", "innerHTML", "execScript", "crypto.subtle",
                "WebSocket", "DOMParser", "RegExp", "atob", "btoa"
            ],
            "python": [
                "eval", "exec", "compile", "subprocess.call", "subprocess.Popen",
                "os.system", "os.popen", "pickle.loads", "yaml.load",
                "__import__", "importlib.import_module", "builtins.__dict__"
            ],
            "ruby": [
                "eval", "system", "exec", "syscall", "IO.popen", "Open3.popen",
                "Object.const_get", "Kernel.load", "Kernel.require", "ERB.new"
            ]
        }
        
      
        risky_funcs = high_risk_functions.get(parsed.language, [])
        
       
        for func in parsed.functions:
            name = func.get("name", "").lower()
            
          
            if any(risk in name for risk in risky_funcs):
                suspicious.append({
                    "name": func.get("name", ""),
                    "line": func.get("line", 0),
                    "args": func.get("args", []),
                    "risk": "high"
                })
            
            
            elif any(pattern in name for pattern in ["hack", "exploit", "shell", "inject", "bypass"]):
                suspicious.append({
                    "name": func.get("name", ""),
                    "line": func.get("line", 0),
                    "args": func.get("args", []),
                    "risk": "medium"
                })
        
        return suspicious
    
    def _find_suspicious_variables(self, parsed: ParsedCode) -> List[Dict[str, Any]]:
        """
        Find suspicious variables.
        
        Args:
            parsed: Parsed code
            
        Returns:
            List of suspicious variables
        """
        suspicious = []
        
       
        for var in parsed.variables:
            name = var.get("name", "").lower()
            value = var.get("value", "")
            
           
            if any(pattern in name for pattern in ["password", "token", "key", "secret", "credential"]):
                suspicious.append({
                    "name": var.get("name", ""),
                    "line": var.get("line", 0),
                    "type": "sensitive_data",
                    "risk": "medium"
                })
            
           
            elif isinstance(value, str) and len(value) > 20:
                if re.match(r'^[A-Za-z0-9+/]+={0,2}$', value):
                    suspicious.append({
                        "name": var.get("name", ""),
                        "line": var.get("line", 0),
                        "type": "encoded_value",
                        "risk": "medium"
                    })
        
        return suspicious
    
    def _analyze_control_flow(self, parsed: ParsedCode) -> List[Dict[str, Any]]:
        """
        Analyze control flow for suspicious patterns.
        
        Args:
            parsed: Parsed code
            
        Returns:
            List of control flow issues
        """
        issues = []
        
       
        for loop in parsed.loops:
            for call in loop.get("calls", []):
                if call.get("name", "").lower() in ["eval", "exec", "Function"]:
                    issues.append({
                        "type": "eval_in_loop",
                        "line": call.get("line", 0),
                        "risk": "high",
                        "description": "Eval used inside a loop can be used for obfuscation or dynamic code execution"
                    })
        
        
        if len(parsed.conditions) > 20:
            issues.append({
                "type": "excessive_conditions",
                "count": len(parsed.conditions),
                "risk": "medium",
                "description": "Excessive number of conditions may indicate control flow obfuscation"
            })
        
        
        for exc in parsed.exceptions:
            
            if not exc.get("handler_body"):
                issues.append({
                    "type": "empty_catch",
                    "line": exc.get("line", 0),
                    "risk": "low",
                    "description": "Empty catch block can hide errors"
                })
        
        return issues
    
    def _analyze_data_flow(self, parsed: ParsedCode) -> List[Dict[str, Any]]:
        """
        Analyze data flow for suspicious patterns.
        
        Args:
            parsed: Parsed code
            
        Returns:
            List of data flow issues
        """
        issues = []
        
        
        var_assignments = {var.get("name"): var for var in parsed.variables if "name" in var}
        
       
        for call in parsed.function_calls:
            for arg in call.get("args", []):
                if isinstance(arg, str) and arg in var_assignments:
                   
                    pass
                elif isinstance(arg, str) and arg not in var_assignments:
                    issues.append({
                        "type": "uninitialized_variable",
                        "line": call.get("line", 0),
                        "variable": arg,
                        "risk": "low",
                        "description": "Variable used without initialization"
                    })
        
       
        input_vars = set()
        dangerous_funcs = ["eval", "exec", "system", "shell_exec", "include"]
        
        
        for call in parsed.function_calls:
            name = call.get("name", "").lower()
            if name in ["_get", "_post", "_request", "input", "readline"]:
                for target in call.get("targets", []):
                    input_vars.add(target)
        
       
        for call in parsed.function_calls:
            name = call.get("name", "").lower()
            if name in dangerous_funcs:
                for arg in call.get("args", []):
                    if isinstance(arg, str) and arg in input_vars:
                        issues.append({
                            "type": "user_input_in_dangerous_function",
                            "line": call.get("line", 0),
                            "function": name,
                            "variable": arg,
                            "risk": "high",
                            "description": "User input used in dangerous function"
                        })
        
        return issues
    
    def _identify_behaviors(self, parsed: ParsedCode) -> List[Dict[str, Any]]:
        """
        Identify potential behaviors based on code analysis.
        
        Args:
            parsed: Parsed code
            
        Returns:
            List of identified behaviors
        """
        behaviors = []
        
        
        if self._has_network_access(parsed):
            behaviors.append({
                "type": "network_access",
                "risk": "medium",
                "description": "Code attempts to make network connections"
            })
        
        
        if self._has_file_access(parsed):
            behaviors.append({
                "type": "file_system_access",
                "risk": "medium",
                "description": "Code attempts to access the file system"
            })
        
        
        if self._has_data_exfiltration(parsed):
            behaviors.append({
                "type": "data_exfiltration",
                "risk": "high",
                "description": "Code appears to be exfiltrating data"
            })
        
        
        if self._has_persistence(parsed):
            behaviors.append({
                "type": "persistence",
                "risk": "high",
                "description": "Code attempts to establish persistence"
            })
        
        
        if self._has_command_execution(parsed):
            behaviors.append({
                "type": "command_execution",
                "risk": "critical",
                "description": "Code executes system commands"
            })
        
        
        if self._has_obfuscation(parsed):
            behaviors.append({
                "type": "obfuscation",
                "risk": "high",
                "description": "Code uses obfuscation techniques"
            })
        
        return behaviors
    
    def _has_network_access(self, parsed: ParsedCode) -> bool:
        """
        Check if code has network access.
        
        Args:
            parsed: Parsed code
            
        Returns:
            True if code has network access, False otherwise
        """
        network_functions = {
            "php": ["curl_init", "fsockopen", "socket_create", "stream_socket_client", "file_get_contents"],
            "javascript": ["fetch", "XMLHttpRequest", "WebSocket", "ajax", "$.get", "$.post"],
            "python": ["urllib", "requests", "http", "socket", "ftplib", "smtplib"],
            "ruby": ["Net::HTTP", "TCPSocket", "open-uri", "RestClient"]
        }
        
        funcs = network_functions.get(parsed.language, [])
        
        for call in parsed.function_calls:
            name = call.get("name", "").lower()
            if any(func.lower() in name for func in funcs):
                return True
        
        return False
    
    def _has_file_access(self, parsed: ParsedCode) -> bool:
        """
        Check if code has file system access.
        
        Args:
            parsed: Parsed code
            
        Returns:
            True if code has file access, False otherwise
        """
        file_functions = {
            "php": ["fopen", "file_get_contents", "file_put_contents", "unlink", "mkdir"],
            "javascript": ["fs.readFile", "fs.writeFile", "fs.unlink", "fs.mkdir"],
            "python": ["open", "os.remove", "os.unlink", "os.mkdir", "shutil"],
            "ruby": ["File.open", "File.read", "File.write", "File.delete", "Dir.mkdir"]
        }
        
        funcs = file_functions.get(parsed.language, [])
        
        for call in parsed.function_calls:
            name = call.get("name", "").lower()
            if any(func.lower() in name for func in funcs):
                return True
        
        return False
    
    def _has_data_exfiltration(self, parsed: ParsedCode) -> bool:
        """
        Check if code has data exfiltration patterns.
        
        Args:
            parsed: Parsed code
            
        Returns:
            True if code has data exfiltration, False otherwise
        """
        
        if not self._has_network_access(parsed):
            return False
        
        sensitive_vars = []
        for var in parsed.variables:
            name = var.get("name", "").lower()
            if any(pattern in name for pattern in ["password", "token", "key", "secret", "credential", "config", "database"]):
                sensitive_vars.append(var.get("name"))
        
        if not sensitive_vars:
            return False
        
        # Check if sensitive variables are used in network calls
        for call in parsed.function_calls:
            if self._is_network_call(call, parsed.language):
                for arg in call.get("args", []):
                    if isinstance(arg, str) and arg in sensitive_vars:
                        return True
        
        return False
    
    def _is_network_call(self, call: Dict[str, Any], language: str) -> bool:
        """
        Check if function call is a network call.
        
        Args:
            call: Function call information
            language: Code language
            
        Returns:
            True if function is a network call, False otherwise
        """
        network_functions = {
            "php": ["curl_init", "fsockopen", "socket_create", "stream_socket_client", "file_get_contents"],
            "javascript": ["fetch", "XMLHttpRequest", "WebSocket", "ajax", "$.get", "$.post"],
            "python": ["urllib", "requests", "http", "socket", "ftplib", "smtplib"],
            "ruby": ["Net::HTTP", "TCPSocket", "open-uri", "RestClient"]
        }
        
        funcs = network_functions.get(language, [])
        name = call.get("name", "").lower()
        
        return any(func.lower() in name for func in funcs)
    
    def _has_persistence(self, parsed: ParsedCode) -> bool:
        """
        Check if code has persistence mechanisms.
        
        Args:
            parsed: Parsed code
            
        Returns:
            True if code has persistence mechanisms, False otherwise
        """
        persistence_functions = {
            "php": ["cron", "autoload", "register_shutdown_function", "set_include_path"],
            "javascript": ["localStorage", "sessionStorage", "cookie", "register", "startup"],
            "python": ["cron", "scheduler", "startup", "daemon", "service"],
            "ruby": ["cron", "daemon", "service", "startup"]
        }
        
        funcs = persistence_functions.get(parsed.language, [])
        
        for call in parsed.function_calls:
            name = call.get("name", "").lower()
            if any(func.lower() in name for func in funcs):
                return True
        
        
        system_dirs = ["/etc", "/var", "/usr", "/lib", "/bin", "/sbin", "/boot", "/sys", "/root", "system32", "Windows"]
        
        if self._has_file_access(parsed):
            for call in parsed.function_calls:
                if self._is_file_write(call, parsed.language):
                    for arg in call.get("args", []):
                        if isinstance(arg, str) and any(sd in arg for sd in system_dirs):
                            return True
        
        return False
    
    def _is_file_write(self, call: Dict[str, Any], language: str) -> bool:
        """
        Check if function call is a file write operation.
        
        Args:
            call: Function call information
            language: Code language
            
        Returns:
            True if function is a file write, False otherwise
        """
        write_functions = {
            "php": ["fwrite", "file_put_contents", "fputs"],
            "javascript": ["fs.writeFile", "fs.appendFile", "write"],
            "python": ["write", "open.+w", "open.+a"],
            "ruby": ["write", "puts", "append"]
        }
        
        funcs = write_functions.get(language, [])
        name = call.get("name", "").lower()
        
        return any(re.search(func.lower(), name) for func in funcs)
    
    def _has_command_execution(self, parsed: ParsedCode) -> bool:
        """
        Check if code executes system commands.
        
        Args:
            parsed: Parsed code
            
        Returns:
            True if code executes commands, False otherwise
        """
        exec_functions = {
            "php": ["system", "exec", "shell_exec", "passthru", "proc_open", "popen"],
            "javascript": ["child_process", "spawn", "exec", "execFile"],
            "python": ["os.system", "subprocess", "popen", "exec", "eval"],
            "ruby": ["system", "exec", "spawn", "backtick", "`.*`"]
        }
        
        funcs = exec_functions.get(parsed.language, [])
        
        for call in parsed.function_calls:
            name = call.get("name", "").lower()
            if any(re.search(func.lower(), name) for func in funcs):
                return True
        
        return False
    
    def _has_obfuscation(self, parsed: ParsedCode) -> bool:
        """
        Check if code uses obfuscation techniques.
        
        Args:
            parsed: Parsed code
            
        Returns:
            True if code uses obfuscation, False otherwise
        """
       
        
        
        string_concats = 0
        for expr in parsed.expressions:
            if expr.get("type") == "binary_operation" and expr.get("operator") == "+":
                left = expr.get("left", {})
                right = expr.get("right", {})
                if (left.get("type") == "string" and len(left.get("value", "")) < 3) or \
                   (right.get("type") == "string" and len(right.get("value", "")) < 3):
                    string_concats += 1
        
        if string_concats > 10:
            return True
        
        
        char_code_funcs = ["fromCharCode", "chr", "ord", "char"]
        for call in parsed.function_calls:
            name = call.get("name", "").lower()
            if any(func.lower() in name for func in char_code_funcs):
                return True
        
        
        for call in parsed.function_calls:
            name = call.get("name", "").lower()
            if name in ["eval", "exec", "Function"]:
                for arg in call.get("args", []):
                    
                    if isinstance(arg, dict) and arg.get("type") in ["binary_operation", "call_expression"]:
                        return True
        
        
        short_var_count = 0
        var_count = len(parsed.variables)
        
        for var in parsed.variables:
            name = var.get("name", "")
            if len(name) <= 2:
                short_var_count += 1
        
        if var_count > 20 and (short_var_count / var_count) > 0.5:
            return True
        
        return False
