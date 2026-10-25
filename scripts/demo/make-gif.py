"""Composes the README demo GIF from the frames web/demo/record-demo.mjs captured (M11).

    python scripts/demo/make-gif.py [artifacts/demo] [docs/assets/stolen-session-demo.gif]

Each frame puts the two browser screenshots side by side under their titles, with the step's
caption underneath, and holds it for the duration the recorder chose. Needs Pillow.
"""

import json
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

GAP = 16
HEADER = 54
FOOTER = 62
LEFT_COLOUR = (180, 83, 9)     # amber: the "before"
RIGHT_COLOUR = (21, 128, 61)   # green: ThreatLock
INK = (17, 24, 39)
PAPER = (255, 255, 255)
BAND = (243, 244, 246)


def font(size: int, bold: bool = False) -> ImageFont.ImageFont:
    names = (["segoeuib.ttf", "arialbd.ttf", "DejaVuSans-Bold.ttf"] if bold else ["segoeui.ttf", "arial.ttf", "DejaVuSans.ttf"])
    for name in names:
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default(size)


def pill(draw: ImageDraw.ImageDraw, centre_x: int, y: int, text: str, colour, face) -> None:
    width = draw.textlength(text, font=face)
    left = centre_x - width / 2 - 14
    draw.rounded_rectangle((left, y, left + width + 28, y + 34), radius=17, fill=colour)
    draw.text((centre_x, y + 17), text, font=face, fill=PAPER, anchor="mm")


def compose(frames_dir: Path, out: Path) -> None:
    manifest = json.loads((frames_dir / "manifest.json").read_text(encoding="utf-8"))
    sample = Image.open(frames_dir / manifest["frames"][0]["left"])
    pw, ph = sample.size
    width, height = pw * 2 + GAP * 3, HEADER + ph + FOOTER
    title, caption_face, big = font(19, bold=True), font(19), font(30, bold=True)

    images, durations = [], []
    for frame in manifest["frames"]:
        canvas = Image.new("RGB", (width, height), PAPER)
        draw = ImageDraw.Draw(canvas)
        for i, (name, label, colour) in enumerate(
            [(frame["left"], manifest["leftTitle"], LEFT_COLOUR), (frame["right"], manifest["rightTitle"], RIGHT_COLOUR)]
        ):
            x = GAP + i * (pw + GAP)
            pill(draw, x + pw // 2, 10, label, colour, title)
            canvas.paste(Image.open(frames_dir / name).convert("RGB"), (x, HEADER))
            draw.rectangle((x - 1, HEADER - 1, x + pw, HEADER + ph), outline=colour, width=2)
        draw.rectangle((0, HEADER + ph + 8, width, height), fill=BAND)
        draw.text((width // 2, HEADER + ph + 8 + (FOOTER - 8) // 2), frame["caption"], font=caption_face, fill=INK, anchor="mm")
        images.append(canvas)
        durations.append(frame["ms"])

    # A closing card with the result.
    card = Image.new("RGB", (width, height), PAPER)
    draw = ImageDraw.Draw(card)
    draw.text((width // 2, height // 2 - 70), "Same stolen password. Same Tor exit.", font=big, fill=INK, anchor="mm")
    draw.text((width // 4 + GAP, height // 2), "Observe only: the attacker keeps reading", font=caption_face, fill=LEFT_COLOUR, anchor="mm")
    draw.text((3 * width // 4, height // 2), f"ThreatLock: sessions revoked {manifest['revokedMs']} ms after sign-in", font=caption_face,
              fill=RIGHT_COLOUR, anchor="mm")
    draw.text((width // 2, height // 2 + 70), "Detected by D1, decided by the org's policy, revoked by the Worker, audited, admins told once.",
              font=caption_face, fill=INK, anchor="mm")
    images.append(card)
    durations.append(3500)

    palette = [image.convert("P", palette=Image.Palette.ADAPTIVE, colors=128) for image in images]
    out.parent.mkdir(parents=True, exist_ok=True)
    palette[0].save(out, save_all=True, append_images=palette[1:], duration=durations, loop=0, optimize=True, disposal=2)
    print(f"{out}: {len(images)} frames, {width}x{height}, {out.stat().st_size / 1024:.0f} KiB")


if __name__ == "__main__":
    frames_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "artifacts/demo")
    out = Path(sys.argv[2] if len(sys.argv) > 2 else "docs/assets/stolen-session-demo.gif")
    compose(frames_dir, out)
