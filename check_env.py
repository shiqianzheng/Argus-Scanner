import tree_sitter_languages

print("Checking tree_sitter_languages...")
try:
    java_parser = tree_sitter_languages.get_parser('java')
    print("Java parser: OK")
except Exception as e:
    print(f"Java parser: FAILED - {e}")

try:
    go_parser = tree_sitter_languages.get_parser('go')
    print("Go parser: OK")
except Exception as e:
    print(f"Go parser: FAILED - {e}")
    if "takes exactly 1 argument" in str(e):
        print("💡 建议: 检测到 tree-sitter 版本冲突。请运行 'pip install tree-sitter==0.20.4 tree-sitter-languages==1.10.2' 修复。")
