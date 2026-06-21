import re
import itertools
import string
import os
import json
import random
from collections.abc import Generator

# 定义数据文件路径

BASE_DIR: str = os.path.dirname(__file__)
KEYWORDS_PATH: str = os.path.join(BASE_DIR, "data", "keywords.json")
STRUCTURE_PATH: str = os.path.join(BASE_DIR, "data", "structure.json")
PROPERTY_PATH: str = os.path.join(BASE_DIR, "data", "property_keys.json")
LUA_BUILTINS_PATH: str = os.path.join(BASE_DIR, "data", "lua_builtins.json")
ENUM_LIB_PATH: str = os.path.join(BASE_DIR, "data", "enum_lib.json")
API_PATH: str = os.path.join(BASE_DIR, "data", "api.json")
COMPONENT_PATH: str = os.path.join(BASE_DIR, "data", "component.json")

# 加载数据文件内容到变量中

with open(API_PATH, "r", encoding="utf-8") as f:
    data = json.load(f)
    GLOBAL_APIS: set = set(data.get("api_table", [])) | set(data.get("api_func", []))

with open(COMPONENT_PATH, "r", encoding="utf-8") as f:
    COMPONENT_APIS: set = set(json.load(f)["api"])

with open(ENUM_LIB_PATH, "r", encoding="utf-8") as f:
    ENUM_LIB: set = set(json.load(f).keys())

with open(KEYWORDS_PATH, "r", encoding="utf-8") as f:
    KEYWORDS: set = set(json.load(f))

with open(STRUCTURE_PATH, "r", encoding="utf-8") as f:
    STRUCTURE: set = set(json.load(f))

with open(PROPERTY_PATH, "r", encoding="utf-8") as f:
    PROPERTY_KEYS: set = set(json.load(f))

with open(LUA_BUILTINS_PATH, "r", encoding="utf-8") as f:
    LUA_BUILTINS: set = set(json.load(f))


class UGC3LuaObfuscator:
    """MiniUGC V3 Lua代码混淆器类"""

    def __init__(
        self,
        external_whitelist_path: str | None = None,  # 外部白名单路径
        keep_comments: bool = False,  # 是否保留注释
        preserve_open_fn_args: bool = True,  # 是否保留函数参数
        preserve_propertys: bool = True,  # 是否保留属性
        single_line: bool = False,  # 是否单行输出
    ):
        self.keep_comments: bool = keep_comments  # 是否保留注释
        self.preserve_open_fn_args: bool = preserve_open_fn_args
        self.preserve_propertys: bool = preserve_propertys
        self.single_line: bool = single_line
        self.enum_lib = ENUM_LIB
        self.global_apis = GLOBAL_APIS
        self.component_apis = COMPONENT_APIS
        self.whitelist: set = self._build_whitelist()
        if external_whitelist_path:
            with open(external_whitelist_path, "r", encoding="utf-8") as f:
                external: list = json.load(f)
                if isinstance(external, list):
                    self.whitelist.update(set(external))
                else:
                    raise ValueError("外部白名单JSON必须是标识符数组")
        self.mapping: dict = {}
        self.gen: Generator[str, None, None] = self._name_generator()
        self.pattern = re.compile(
            r"(--[^\n]*)"
            r'|(\[\[[\s\S]*?\]\]|"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\')'
            r"|([_a-zA-Z][_a-zA-Z0-9]*)"
            r"|([^\s])"
            r"|(\s+)"
        )

    def _build_whitelist(self) -> set:
        """构建白名单，包含关键字、结构体、属性、Lua内置函数、枚举库中的标识符
        Returns:
            set: 白名单集合
        """
        return (
            KEYWORDS | STRUCTURE | PROPERTY_KEYS | LUA_BUILTINS
        )  # 保留关键字、结构体、属性、Lua内置函数

    def _protect_long_brackets(self, source_code: str) -> tuple[str, dict[str, str]]:
        """将长字符串/长注释 [=[...]=] 替换为占位符（跳过常规引号字符串内部）
        Args:
            source_code (str): 原始代码
        Returns:
            tuple[str, dict[str, str]]: 处理后的代码和占位符字典
        """
        placeholders: dict[str, str] = {}
        counter = 0
        result: list[str] = []  # 结果列表
        i: int = 0  # 当前索引
        n: int = len(source_code)  # 原始代码长度

        while i < n:
            ch: str = source_code[i]

            # 1. 常规引号字符串 "..." 或 '...'（跳过转义）
            if ch in ('"', "'"):
                quote = ch
                result.append(ch)
                i += 1
                while i < n:
                    c = source_code[i]
                    if c == "\\":
                        result.append(c)
                        i += 1
                        if i < n:
                            result.append(source_code[i])
                            i += 1
                    elif c == quote:
                        result.append(c)
                        i += 1
                        break
                    else:
                        result.append(c)
                        i += 1
                continue

            # 2. 长注释 --[=*[...]=*]
            if (
                source_code[i : i + 2] == "--"
                and i + 2 < n
                and source_code[i + 2] == "["
            ):
                j = i + 3
                while j < n and source_code[j] == "=":
                    j += 1
                if j < n and source_code[j] == "[":
                    close = "]" + source_code[i + 3 : j] + "]"
                    end = source_code.find(close, j + 1)
                    if end != -1:
                        end += len(close)
                    else:
                        end = n
                    key = f"\x00LBC{counter}\x00"
                    placeholders[key] = source_code[i:end]
                    result.append(key)
                    i = end
                    counter += 1
                    continue
                # --[ 但不是 --[=*[ → 回退为普通单行注释

            # 3. 长字符串 [=*[...]=*]（不以 -- 开头）
            if ch == "[" and i + 1 < n:
                j = i + 1
                while j < n and source_code[j] == "=":
                    j += 1
                if j < n and source_code[j] == "[":
                    close = "]" + source_code[i + 1 : j] + "]"
                    end = source_code.find(close, j + 1)
                    if end != -1:
                        end += len(close)
                        key = f"\x00LBS{counter}\x00"
                        placeholders[key] = source_code[i:end]
                        result.append(key)
                        i = end
                        counter += 1
                        continue

            # 4. 单行注释 --
            if source_code[i : i + 2] == "--":
                end = source_code.find("\n", i + 2)
                if end == -1:
                    end = n
                result.append(source_code[i:end])
                i = end
                continue

            result.append(ch)
            i += 1

        return "".join(result), placeholders

    @staticmethod
    def _restore_long_brackets(code: str, placeholders: dict[str, str]) -> str:
        """将占位符还原为原始长括号内容
        Args:
            code (str): 原始代码
            placeholders (dict[str, str]): 占位符字典
        Returns:
            str: 处理后的代码
        """
        for placeholder, original in placeholders.items():
            code = code.replace(placeholder, original)
        return code

    def _name_generator(self) -> Generator[str, None, None]:
        digits = list("0123456789abcdef")
        for length in itertools.count(1):
            for combo in itertools.product(digits, repeat=length):
                yield "_" + "".join(combo)

    def _extract_table_keys(self, source_code: str, table_name: str) -> set:
        """提取表中的标识符
        Args:
            source_code (str): 原始代码
            table_name (str): 表名
        Returns:
            set: 表中的标识符集合
        """
        table_keys: set[str] = set()
        table_pattern: re.Pattern = re.compile(
            rf"(?:local\s+)?{re.escape(table_name)}\s*=\s*\{{"
        )  # 匹配 table_name = { 开头的代码片段
        for match in table_pattern.finditer(source_code):
            start: int = match.end() - 1
            depth: int = 0
            i: int = start
            in_string: str | None = None
            escape: bool = False
            long_close: str | None = None
            while i < len(source_code):
                ch = source_code[i]
                if long_close is not None:
                    lb_len = len(long_close)
                    if (
                        i + lb_len <= len(source_code)
                        and source_code[i : i + lb_len] == long_close
                    ):
                        i += lb_len
                        long_close = None
                        continue
                elif in_string:
                    if escape:
                        escape = False
                    elif ch == "\\":
                        escape = True
                    elif ch == in_string:
                        in_string = None
                else:
                    if ch == "[":
                        j = i + 1
                        while j < len(source_code) and source_code[j] == "=":
                            j += 1
                        if j < len(source_code) and source_code[j] == "[":
                            long_close = "]" + "=" * (j - i - 1) + "]"
                            i = j
                            continue
                    if ch in ('"', "'"):
                        in_string = ch
                    elif source_code[i : i + 2] == "--":
                        # 长注释 --[=[...]=] 层级支持
                        j = i + 2
                        if j < len(source_code) and source_code[j] == "[":
                            k = j + 1
                            while k < len(source_code) and source_code[k] == "=":
                                k += 1
                            if k < len(source_code) and source_code[k] == "[":
                                close = "]" + source_code[j + 1 : k] + "]"
                                end = source_code.find(close, k + 1)
                                i = end + len(close) if end != -1 else len(source_code)
                                continue
                        # 单行注释 --
                        end = source_code.find("\n", i + 2)
                        i = end + 1 if end != -1 else len(source_code)
                        continue
                    elif ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                        if depth == 0:
                            table_body = source_code[start + 1 : i]
                            table_keys.update(self._parse_open_fn_args_keys(table_body))
                            break
                i += 1
        return table_keys

    def _extract_open_fn_args(self, source_code: str) -> set:
        """提取函数参数表中的标识符
        Args:
            source_code (str): 原始代码
        Returns:
            set: 函数参数表中的标识符集合
        """
        return self._extract_table_keys(source_code, "openFnArgs")

    def _extract_propertys_keys(self, source_code: str) -> set:
        """提取属性表中的标识符
        Args:
            source_code (str): 原始代码
        Returns:
            set: 属性表中的标识符集合
        """
        return self._extract_table_keys(source_code, "propertys")

    def _parse_open_fn_args_keys(self, body: str) -> set:
        """解析函数参数表中的标识符
        Args:
            body (str): 函数参数表的代码
        Returns:
            set: 函数参数表中的标识符集合
        """
        keys = set()
        i = 0
        while i < len(body):
            ch = body[i]
            if ch in ('"', "'"):
                quote = ch
                i += 1
                while i < len(body):
                    if body[i] == "\\":
                        i += 2
                    elif body[i] == quote:
                        i += 1
                        break
                    else:
                        i += 1
                continue  # 长字符串 [=[...]=] 层级支持
            if ch == "[" and i + 1 < len(body):
                j = i + 1
                while j < len(body) and body[j] == "=":
                    j += 1
                if j < len(body) and body[j] == "[":
                    close = "]" + body[i + 1 : j] + "]"
                    end = body.find(close, j + 1)
                    i = end + len(close) if end != -1 else len(body)
                    continue
            if body[i : i + 2] == "--":
                # 长注释 --[=[...]=] 层级支持
                j = i + 2
                if j < len(body) and body[j] == "[":
                    k = j + 1
                    while k < len(body) and body[k] == "=":
                        k += 1
                    if k < len(body) and body[k] == "[":
                        close = "]" + body[j + 1 : k] + "]"
                        end = body.find(close, k + 1)
                        i = end + len(close) if end != -1 else len(body)
                        continue
                # 单行注释 --
                end = body.find("\n", i + 2)
                i = end + 1 if end != -1 else len(body)
                continue
            if ch.isspace() or ch == ",":
                i += 1
                continue
            if ch == "{":
                depth = 1
                i += 1
                while i < len(body) and depth > 0:
                    if body[i] in ('"', "'"):
                        quote = body[i]
                        i += 1
                        while i < len(body):
                            if body[i] == "\\":
                                i += 2
                            elif body[i] == quote:
                                i += 1
                                break
                            else:
                                i += 1
                        continue
                    # 长字符串 [=[...]=] 层级支持
                    if body[i] == "[":
                        j = i + 1
                        while j < len(body) and body[j] == "=":
                            j += 1
                        if j < len(body) and body[j] == "[":
                            close = "]" + body[i + 1 : j] + "]"
                            end = body.find(close, j + 1)
                            i = end + len(close) if end != -1 else len(body)
                            continue
                    if body[i : i + 2] == "--":
                        j = i + 2
                        if j < len(body) and body[j] == "[":
                            k = j + 1
                            while k < len(body) and body[k] == "=":
                                k += 1
                            if k < len(body) and body[k] == "[":
                                close = "]" + body[j + 1 : k] + "]"
                                end = body.find(close, k + 1)
                                i = end + len(close) if end != -1 else len(body)
                                continue
                        end = body.find("\n", i + 2)
                        i = end + 1 if end != -1 else len(body)
                        continue
                    if body[i] == "{":
                        depth += 1
                    elif body[i] == "}":
                        depth -= 1
                    i += 1
                continue
            if ch == "[":
                j = i + 1
                while j < len(body) and body[j].isspace():
                    j += 1
                if j < len(body) and body[j] in ('"', "'"):
                    quote = body[j]
                    j += 1
                    key_start = j
                    while j < len(body):
                        if body[j] == "\\":
                            j += 2
                        elif body[j] == quote:
                            key = body[key_start:j]
                            j += 1
                            break
                        else:
                            j += 1
                    else:
                        i += 1
                        continue
                    while j < len(body) and body[j].isspace():
                        j += 1
                    if j < len(body) and body[j] == "]":
                        j += 1
                        while j < len(body) and body[j].isspace():
                            j += 1
                        if j < len(body) and body[j] == "=":
                            keys.add(key)
                            i = j + 1
                            continue
                i += 1
                continue
            if ch.isalpha() or ch == "_":
                start = i
                i += 1
                while i < len(body) and (body[i].isalnum() or body[i] == "_"):
                    i += 1
                token = body[start:i]
                j = i
                while j < len(body) and body[j].isspace():
                    j += 1
                if j < len(body) and body[j] == "=":
                    keys.add(token)
                    i = j + 1
                    continue
                continue
            i += 1
        return keys

    def _get_obfuscated_name(self, original: str) -> str:
        if original not in self.mapping:
            self.mapping[original] = next(self.gen)
        return self.mapping[original]

    def obfuscate(self, source_code: str) -> str:
        # 匹配优先级: 块注释/行注释 > 块字符串/引号字符串 > 标识符 > 其他符号 > 空白符
        # 先保护长括号，避免其内部标识符被混淆
        protected_code, placeholders = self._protect_long_brackets(source_code)

        result_parts = []
        prev_non_space_token = None
        prev_non_space_prev_token = None
        alias_sources = self.global_apis | self.component_apis | self.enum_lib
        enum_aliases = set()
        dynamic_whitelist = set(self.whitelist)
        if self.preserve_open_fn_args:
            dynamic_whitelist |= self._extract_open_fn_args(source_code)
        if self.preserve_propertys:
            dynamic_whitelist |= self._extract_propertys_keys(source_code)

        for match in self.pattern.finditer(protected_code):
            token = match.group(0)
            if match.group(1):
                if self.keep_comments:
                    result_parts.append(token)
                continue
            if match.group(2):
                result_parts.append(token)
                continue
            if match.group(5):
                if self.single_line:
                    if not result_parts or result_parts[-1] != " ":
                        result_parts.append(" ")
                else:
                    result_parts.append(token)
                continue
            if match.group(3):
                ident = match.group(3)
                global_dot_alias = (
                    prev_non_space_token == "."
                    and prev_non_space_prev_token == "_G"
                    and ident in alias_sources
                )
                preserve_enum_member = prev_non_space_token == "." and (
                    prev_non_space_prev_token in self.enum_lib
                    or prev_non_space_prev_token in enum_aliases
                )
                if global_dot_alias:
                    if (
                        len(result_parts) >= 2
                        and result_parts[-1] == "."
                        and result_parts[-2] == "_G"
                    ):
                        result_parts.pop()
                        result_parts.pop()
                    obfuscated = self._get_obfuscated_name(ident)
                    if ident in self.enum_lib:
                        enum_aliases.add(obfuscated)
                    result_parts.append(obfuscated)
                    prev_non_space_prev_token = None
                    prev_non_space_token = obfuscated
                elif preserve_enum_member or ident in dynamic_whitelist:
                    result_parts.append(ident)
                    prev_non_space_prev_token = prev_non_space_token
                    prev_non_space_token = ident
                else:
                    obfuscated = self._get_obfuscated_name(ident)
                    if ident in self.enum_lib:
                        enum_aliases.add(obfuscated)
                    result_parts.append(obfuscated)
                    prev_non_space_prev_token = prev_non_space_token
                    prev_non_space_token = ident
                continue
            result_parts.append(token)
            if token.strip():
                prev_non_space_prev_token = prev_non_space_token
                prev_non_space_token = token

        obfuscated_code = "".join(result_parts)
        obfuscated_code = self._restore_long_brackets(obfuscated_code, placeholders)
        api_aliases = {
            original: obfuscated
            for original, obfuscated in self.mapping.items()
            if original in alias_sources
        }
        if api_aliases:
            bom = ""
            if obfuscated_code.startswith("\ufeff"):
                bom = "\ufeff"
                obfuscated_code = obfuscated_code[1:]
            alias_lines = "".join(
                f"local {alias} = _G.{original}\n"
                for original, alias in api_aliases.items()
            )
            obfuscated_code = bom + alias_lines + obfuscated_code

        return obfuscated_code

    def deobfuscate(self, source_code: str, reverse_mapping: dict) -> str:
        protected_code, placeholders = self._protect_long_brackets(source_code)
        result_parts = []
        for match in self.pattern.finditer(protected_code):
            token = match.group(0)
            if match.group(1) or match.group(2):
                result_parts.append(token)
            elif match.group(3):
                ident = match.group(3)
                if ident in reverse_mapping:
                    result_parts.append(reverse_mapping[ident])
                else:
                    result_parts.append(ident)
            else:
                result_parts.append(token)

        result = "".join(result_parts)
        return self._restore_long_brackets(result, placeholders)


def debug() -> None:
    print("\n1. 输出固定白名单")
    choice: str = input("请选择操作: ")
    if choice == "1":
        PRINT_MAPPING = {
            "1": KEYWORDS,
            "2": STRUCTURE,
            "3": PROPERTY_KEYS,
            "4": ENUM_LIB,
            "5": GLOBAL_APIS,
            "6": COMPONENT_APIS,
            "7": LUA_BUILTINS,
        }
        print("\n选择固定白名单")
        print("1. Lua 关键字")
        print("2. UGC 结构保留词与固定字段")
        print("3. 组件属性固定 Key")
        print("4. UGC 枚举库")
        print("5. 官方全局 API")
        print("6. 组件函数")
        print("7. Lua 内置全局函数和库名")
        sub_choice: str = input("请选择要查看的白名单类别: ")
        if sub_choice in PRINT_MAPPING:
            print(PRINT_MAPPING[sub_choice])


def main() -> None:
    while True:
        print("\n1. 混淆文件")
        print("2. 解除混淆")
        print("3. Debug")
        print("4. 退出")
        choice: str = input("请选择操作: ")
        if choice == "1":
            input_path = input("请输入文件路径: ")
            with open(input_path, "r", encoding="utf-8") as f:
                code = f.read()
            external_whitelist: str | None = (
                input("请输入外部白名单JSON文件路径 (可选，直接回车跳过): ").strip()
                or None
            )
            preserve_open_fn_args = (
                input("是否保留 openFnArgs 中的函数名？(Y/n): ").strip().lower()
            )
            preserve_propertys = (
                input("是否保留 propertys 表中的变量名？(Y/n): ").strip().lower()
            )
            preserve_open_fn_args_flag = preserve_open_fn_args not in ("n", "no")
            preserve_propertys_flag = preserve_propertys not in ("n", "no")
            single_line = input("是否输出单行化结果？(Y/n): ").strip().lower()
            single_line_flag = single_line not in ("n", "no")
            obfuscator = UGC3LuaObfuscator(
                external_whitelist_path=external_whitelist,
                preserve_open_fn_args=preserve_open_fn_args_flag,
                preserve_propertys=preserve_propertys_flag,
                single_line=single_line_flag,
            )
            obfuscated_code = obfuscator.obfuscate(code)

            output_path: str = input("请输入输出文件路径: ")
            if os.path.isdir(output_path):
                print("错误: 输出路径不能是目录。请提供一个文件路径。")
                continue
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(obfuscated_code)
            # 保存映射文件
            mapping_path: str = output_path + ".mapping.json"
            with open(mapping_path, "w", encoding="utf-8") as f:
                json.dump(obfuscator.mapping, f, ensure_ascii=False, indent=4)
            print(f"混淆完成. 已保存至: {output_path}")
            print(f"映射文件已保存至: {mapping_path}")
            print(f"共替换 {len(obfuscator.mapping)} 个标识符.")
        elif choice == "2":
            mapping_path: str = input("请输入映射文件路径: ")
            with open(mapping_path, "r", encoding="utf-8") as f:
                mapping = json.load(f)
            reverse_mapping: dict[str, str] = {v: k for k, v in mapping.items()}

            input_path: str = input("请输入混淆文件路径: ")
            with open(input_path, "r", encoding="utf-8") as f:
                code = f.read()

            output_path: str = input("请输入输出文件路径: ")
            if os.path.isdir(output_path):
                print("错误: 输出路径不能是目录。请提供一个文件路径。")
                continue
            obfuscator = UGC3LuaObfuscator()
            deobfuscated_code = obfuscator.deobfuscate(code, reverse_mapping)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(deobfuscated_code)
            print(f"解除混淆完成. 已保存至: {output_path}")
        elif choice == "3":
            debug()
        elif choice == "4":
            print("退出程序\n")
            break
        else:
            print("输入错误, 请重新输入")


if __name__ == "__main__":
    main()
