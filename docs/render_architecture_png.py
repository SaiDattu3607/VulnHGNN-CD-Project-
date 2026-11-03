from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "vulnhgnn_full_architecture_with_llm_review.png"
WIDTH, HEIGHT = 2600, 1860

BG = "#F3F6F3"
INK = "#142A30"
MUTED = "#5C7072"
LINE = "#9BAEAA"
WHITE = "#FFFFFF"
GREEN = "#176B57"
TEAL = "#287E83"
BLUE = "#3D6F91"
ORANGE = "#D66A43"
GOLD = "#D2A134"
PALE_GREEN = "#E4F1EB"
PALE_ORANGE = "#F8E9E1"
PALE_BLUE = "#E6EEF4"
PALE_GOLD = "#F5EFD9"

FONT_REGULAR = r"C:\Windows\Fonts\segoeui.ttf"
FONT_BOLD = r"C:\Windows\Fonts\segoeuib.ttf"

image = Image.new("RGB", (WIDTH, HEIGHT), BG)
draw = ImageDraw.Draw(image)


def font(size, bold=False):
    return ImageFont.truetype(FONT_BOLD if bold else FONT_REGULAR, size)


def text_width(text, selected_font):
    box = draw.textbbox((0, 0), text, font=selected_font)
    return box[2] - box[0]


def wrap_text(text, selected_font, max_width):
    words = text.split()
    lines = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if current and text_width(candidate, selected_font) > max_width:
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    return lines


def paragraph(text, x, y, max_width, selected_font, fill, leading=31):
    for line in wrap_text(text, selected_font, max_width):
        draw.text((x, y), line, font=selected_font, fill=fill)
        y += leading
    return y


def pill(text, x, y, color, selected_font=None):
    selected_font = selected_font or font(17, True)
    pad_x, pad_y = 13, 7
    width = text_width(text, selected_font) + pad_x * 2
    height = 31
    draw.rounded_rectangle((x, y, x + width, y + height), radius=14, fill=color)
    draw.text((x + pad_x, y + pad_y - 1), text, font=selected_font, fill=WHITE)
    return width


def card(x, y, width, height, title, items, accent, badge=None, fill=WHITE):
    draw.rounded_rectangle(
        (x, y, x + width, y + height), radius=19, fill=fill,
        outline="#D6E0DB", width=2,
    )
    draw.rounded_rectangle((x, y, x + 10, y + height), radius=5, fill=accent)
    cursor_y = y + 24
    if badge:
        pill(badge, x + 24, cursor_y, accent)
        cursor_y += 47
    title_font = font(29, True)
    cursor_y = paragraph(title, x + 25, cursor_y, width - 50, title_font, INK, 34)
    cursor_y += 15
    body_font = font(22)
    for item in items:
        draw.ellipse((x + 27, cursor_y + 8, x + 36, cursor_y + 17), fill=accent)
        lines = wrap_text(item, body_font, width - 76)
        for index, line in enumerate(lines):
            draw.text((x + 49, cursor_y), line, font=body_font, fill=MUTED)
            cursor_y += 29
        cursor_y += 10


def arrow(start, end, color=LINE, width=7, head=17):
    draw.line((start, end), fill=color, width=width)
    x1, y1 = start
    x2, y2 = end
    if abs(x2 - x1) >= abs(y2 - y1):
        direction = 1 if x2 >= x1 else -1
        points = [(x2, y2), (x2 - direction * head, y2 - head), (x2 - direction * head, y2 + head)]
    else:
        direction = 1 if y2 >= y1 else -1
        points = [(x2, y2), (x2 - head, y2 - direction * head), (x2 + head, y2 - direction * head)]
    draw.polygon(points, fill=color)


# Header
draw.text((76, 42), "VulnHGNN", font=font(54, True), fill=INK)
draw.text(
    (79, 112),
    "End-to-end vulnerability detection, localization, and verified self-healing",
    font=font(27), fill=MUTED,
)
pill("EXISTING SYSTEM", 80, 174, GREEN)
pill("SECURITY + OPTIONAL LLM REVIEW", 294, 174, ORANGE)
draw.text((WIDTH - 540, 180), "SYSTEM ARCHITECTURE  /  2026", font=font(19, True), fill=MUTED)

# Main processing lane
draw.text((78, 253), "01  /  RUNTIME ANALYSIS", font=font(20, True), fill=GREEN)
cards = [
    (70, 300, 290, 385, "Entry points", ["Browser UI to Flask API", "CLI pipeline for source files"], GREEN, "EXISTING"),
    (380, 300, 340, 385, "Input security", ["Request body capped", "Source: non-empty, no NUL, max 1 MB", "LLVM IR: size and structure checks"], ORANGE, "HARDENED"),
    (740, 300, 285, 385, "Compile", ["C / C++ source", "Clang produces LLVM IR", "Temporary IR is cleaned up"], TEAL, "EXISTING"),
    (1045, 300, 330, 385, "Build code graph", ["Parse functions, blocks, instructions", "Create graph nodes and flow edges", "Extract instruction features"], BLUE, "EXISTING"),
    (1395, 300, 300, 385, "Detect", ["Load trained VulnGAT checkpoint", "Graph-based multi-label inference", "Return CWE scores and confidence"], GREEN, "EXISTING"),
    (1715, 300, 330, 385, "Localize and repair", ["Rank suspicious instructions", "Apply available IR repair rules", "Record applied patches"], TEAL, "EXISTING"),
    (2065, 300, 465, 385, "Verify and decide", ["Re-run GNN on patched IR", "Check remaining and newly introduced CWEs", "Log stop / continue decision", "API iteration limit: 1 to 5"], ORANGE, "AGENT UPDATE"),
]

for values in cards:
    card(*values)

# Directional flow through the seven runtime components
for left, right in zip(cards, cards[1:]):
    arrow((left[0] + left[2] + 5, 492), (right[0] - 7, 492))

# Feedback path from validation to another analysis pass
loop_color = ORANGE
draw.line((2295, 685, 2295, 755), fill=loop_color, width=6)
draw.line((2295, 755, 1545, 755), fill=loop_color, width=6)
arrow((1545, 755), (1545, 685), color=loop_color, width=6, head=15)
draw.rounded_rectangle((1640, 722, 2200, 789), radius=14, fill=PALE_ORANGE)
draw.text((1660, 738), "Issues remain + budget left: analyze patched IR again", font=font(19, True), fill=INK)
draw.text((80, 745), "STOP CONDITIONS", font=font(17, True), fill=MUTED)
draw.text((80, 773), "Clean  |  no repair  |  new issue  |  error  |  iteration limit", font=font(18), fill=MUTED)

# Optional external LLM review path
draw.text((78, 827), "02  /  OPTIONAL LLM SECURITY REVIEW - WEB ONLY", font=font(20, True), fill=ORANGE)
llm_cards = [
    (70, 865, 520, 230, "User consent", ["Checkbox is off by default", "Only the web analysis route", "Code is limited to 64 KB"], ORANGE, "NEW / OPT-IN"),
    (620, 865, 780, 230, "LLM reviewer", ["OpenAI-compatible provider; key stays server-side", "Returns a separate estimate and findings", "Does not execute code or apply repairs"], BLUE, "OPTIONAL"),
    (1430, 865, 1100, 230, "Privacy and safety", ["Code leaves the app only after explicit consent", "Timeout, response-size, and JSON-schema checks", "LLM result is advisory; GNN score stays separate"], GOLD, "BOUNDED"),
]
for values in llm_cards:
    card(*values)

# Only an explicit browser opt-in routes source to the provider.
draw.line((718, 685, 718, 815), fill=ORANGE, width=5)
draw.line((718, 815, 330, 815), fill=ORANGE, width=5)
arrow((330, 815), (330, 865), color=ORANGE, width=5, head=13)
arrow((590, 980), (620, 980), color=ORANGE, width=5, head=13)
arrow((1400, 980), (1430, 980), color=ORANGE, width=5, head=13)

# Results and observability
draw.text((78, 1140), "03  /  RESULTS AND OBSERVABILITY", font=font(20, True), fill=GREEN)
result_cards = [
    (70, 1185, 770, 215, "Analysis report", ["Detected CWEs, localization, repair log", "Validation status and remaining issues"], GREEN),
    (870, 1185, 770, 215, "Separate security estimates", ["Local GNN estimate from supported CWEs", "Optional LLM estimate and review findings"], BLUE),
    (1670, 1185, 860, 215, "Repairs and metrics", ["Patched IR and CLI result files", "Optional CodeCarbon energy and CO2 metrics"], GOLD),
]
for values in result_cards:
    card(*values)
draw.line((2530, 685, 2570, 685), fill=GREEN, width=6)
draw.line((2570, 685, 2570, 1170), fill=GREEN, width=6)
draw.line((2570, 1170, 455, 1170), fill=GREEN, width=6)
arrow((455, 1170), (455, 1185), color=GREEN, width=6, head=13)
draw.line((1980, 1095, 1980, 1125), fill=ORANGE, width=5)
draw.line((1980, 1125, 1255, 1125), fill=ORANGE, width=5)
arrow((1255, 1125), (1255, 1185), color=ORANGE, width=5, head=13)

# Offline training and model supply
draw.text((78, 1440), "04  /  OFFLINE MODEL DEVELOPMENT", font=font(20, True), fill=GREEN)
offline = [
    (70, 1485, 650, 220, "Training data", ["Labeled vulnerability examples", "Graph datasets and cached features"], BLUE),
    (775, 1485, 650, 220, "Train and evaluate", ["GNN / PyG training scripts", "Metrics and model selection"], TEAL),
    (1480, 1485, 650, 220, "Model checkpoint", ["Selected weights stored under results/", "Loaded by web app or CLI at runtime"], GREEN),
]
for values in offline:
    card(*values)
arrow((720, 1595), (775, 1595), color=LINE, width=6)
arrow((1425, 1595), (1480, 1595), color=LINE, width=6)

# Model supply connection routed around the outside of the main flow.
draw.line((2130, 1595, 2590, 1595), fill=GREEN, width=5)
draw.line((2590, 1595, 2590, 282), fill=GREEN, width=5)
draw.line((2590, 282, 1545, 282), fill=GREEN, width=5)
arrow((1545, 282), (1545, 300), color=GREEN, width=5, head=13)
draw.rounded_rectangle((2100, 254, 2512, 291), radius=12, fill=BG)
draw.text((2114, 260), "trained checkpoint loaded at startup", font=font(17, True), fill=GREEN)

# Footer distinction note
draw.line((78, 1740, 2525, 1740), fill="#CFDAD5", width=2)
draw.text(
    (80, 1758),
    "LLM scope: optional advisory review only; it has no repair tools. Provider receives source only after explicit user consent.",
    font=font(19), fill=MUTED,
)
draw.text((2340, 1800), "VulnHGNN", font=font(16, True), fill=GREEN)

image.save(OUTPUT, format="PNG", optimize=True, dpi=(180, 180))
print(f"Wrote {OUTPUT} ({WIDTH}x{HEIGHT})")