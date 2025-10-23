# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

def process(ctx, cfg):
    val = ctx.get("with") or ctx.get("input") or ctx.get("inputs") or ctx
    if isinstance(val, dict):
        text = val.get("text")
        if text is None and val:
            text = list(val.values())[0]
        if not isinstance(text, str):
            text = str(text) if text is not None else ""
        return {"uppercased": text.upper()}
    else:
        return {"uppercased": str(val).upper() if val is not None else ""}
