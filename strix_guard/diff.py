"""コマンドの差分表示（修正後の確認用）"""
import difflib
import shlex


def command_diff(old: str, new: str, max_len: int = 260) -> str:
    """2つのコマンドの差分を短い文字列にする"""
    try:
        a = shlex.split(old)
        b = shlex.split(new)
    except Exception:
        a, b = old.split(), new.split()

    parts = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(a=a, b=b).get_opcodes():
        if tag == "equal":
            continue
        if tag == "replace" and (i2 - i1) == 1 and (j2 - j1) == 1:
            parts.append(f"{a[i1]} → {b[j1]}")
        else:
            if i1 != i2:
                parts.append("削除: " + " ".join(a[i1:i2]))
            if j1 != j2:
                parts.append("追加: " + " ".join(b[j1:j2]))
    text = " / ".join(parts) if parts else "変更なし"
    return text[:max_len]
