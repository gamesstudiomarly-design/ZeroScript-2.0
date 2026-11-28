# SPDX-License-Identifier: GPL-3.0-or-later
"""ZeroScript 2.0 - UI Builder.

Provides reusable Roblox UI component templates + a visual-builder JSON
schema the frontend renders and the AI can emit directly.
"""
import json

COMPONENTS = {
    "frame": {"className": "Frame", "defaults": {"Size": "UDim2.new(0,200,0,120)",
                                                  "BackgroundColor3": "Color3.fromRGB(30,30,40)"}},
    "textlabel": {"className": "TextLabel", "defaults": {"Text": "Label", "TextSize": 18}},
    "textbutton": {"className": "TextButton", "defaults": {"Text": "Button", "TextSize": 18}},
    "textbox": {"className": "TextBox", "defaults": {"PlaceholderText": "Type..."}},
    "imagelabel": {"className": "ImageLabel", "defaults": {"Image": "rbxassetid://0"}},
    "scrollingframe": {"className": "ScrollingFrame", "defaults": {"CanvasSize": "UDim2.new(0,0,0,0)"}},
    "uilistlayout": {"className": "UIListLayout", "defaults": {"Padding": "UDim.new(0,8)"}},
    "uigridlayout": {"className": "UIGridLayout", "defaults": {"CellSize": "UDim2.new(0,80,0,80)"}},
    "uipadding": {"className": "UIPadding", "defaults": {"PaddingTop": "UDim.new(0,8)"}},
    "uicorner": {"className": "UICorner", "defaults": {"CornerRadius": "UDim.new(0,8)"}},
    "uistroke": {"className": "UIStroke", "defaults": {"Thickness": 1}},
}


def list_components():
    return [{"key": k, **v} for k, v in COMPONENTS.items()]


def build_luau(tree, parent_var="parent"):
    """Convert a builder tree {type, props, children[]} into Luau code."""
    lines = []

    def emit(node, parent, depth=0):
        t = node.get("type") or "frame"
        comp = COMPONENTS.get(t)
        if not comp:
            return
        var = f"ui{depth}_{t}"
        ind = "\t" * depth
        lines.append(f"{ind}local {var} = Instance.new(\"{comp['className']}\")")
        props = dict(comp["defaults"])
        props.update(node.get("props") or {})
        for k, v in props.items():
            if isinstance(v, str) and (v.startswith("UDim") or v.startswith("Color3")
                                       or v.startswith("Vector2") or v.startswith("Enum")
                                       or v.startswith("ColorSequence") or v.startswith("NumberSequence")):
                lines.append(f"{ind}{var}.{k} = {v}")
            elif isinstance(v, bool):
                lines.append(f"{ind}{var}.{k} = {'true' if v else 'false'}")
            elif isinstance(v, (int, float)):
                lines.append(f"{ind}{var}.{k} = {v}")
            else:
                safe = str(v).replace("\\", "\\\\").replace('"', '\\"')
                lines.append(f"{ind}{var}.{k} = \"{safe}\"")
        lines.append(f"{ind}{var}.Parent = {parent}")
        for child in node.get("children") or []:
            emit(child, var, depth + 1)

    root_type = (tree or {}).get("type") or "frame"
    root_comp = COMPONENTS.get(root_type, COMPONENTS["frame"])
    lines.append(f"--!strict")
    lines.append(f"local {parent_var} = Instance.new(\"{root_comp['className']}\")")
    lines.append(f"{parent_var}.Name = \"{parent_var}\"")
    for child in (tree or {}).get("children") or []:
        emit(child, parent_var, 1)
    return "\n".join(lines) + "\n"