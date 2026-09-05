#!/usr/bin/env python3
"""Draw the digest as a picture, with each project's own logo next to its line.

Telegram cannot put an image inside a text message: a bot may only use custom emoji
if it owns a username bought on Fragment, so a real logo has to arrive as a photo.
This module renders the same rows the text digest prints -- same order, same colours --
into a card sent with sendPhoto.

It is optional scenery. Pillow is not a dependency of the engine: if the import fails,
a font is missing or anything else goes wrong, render() returns None and the caller
sends the text digest exactly as before.
"""

import hashlib
import io
import os
import re
import urllib.request

USER_AGENT = "chain-sentry/card"

WIDTH = 960
PAD = 36
LOGO = 34
TEXT_LEFT = PAD + 60
TEXT_RIGHT = WIDTH - PAD - 34   # the colour strip lives in the gap that leaves

BACKGROUND = (14, 17, 22)
CARD = (22, 26, 33)
TEXT = (232, 236, 242)
DIM = (146, 156, 170)
TRACK = (38, 44, 54)
COLOURS = {
    "up": (46, 204, 113),
    "down": (231, 76, 60),
    "warn": (241, 196, 15),
    "flat": (146, 156, 170),
    "info": (52, 152, 219),
    "alarm": (231, 76, 60),
}

FONT_DIRS = [os.path.join(os.environ.get("WINDIR", "C:/Windows"), "Fonts"),
             "/usr/share/fonts/truetype/dejavu", "/Library/Fonts"]
FONT_REGULAR = ["segoeui.ttf", "DejaVuSans.ttf", "Arial.ttf"]
FONT_BOLD = ["segoeuib.ttf", "DejaVuSans-Bold.ttf", "Arial Bold.ttf"]

# Emoji carry the colour in the TEXT message; here the colour is drawn, and the font
# used for the words has no glyph for them -- left in, they come out as empty boxes.
EMOJI = re.compile("[\U0001F000-\U0001FAFF\u2190-\u21FF\u2600-\u27BF\uFE0F\u20E3]+")


def _font(names, size):
    from PIL import ImageFont
    for directory in FONT_DIRS:
        for name in names:
            path = os.path.join(directory, name)
            if os.path.isfile(path):
                return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def _plain(value):
    """Row text is written for Telegram's HTML, which a picture cannot show."""
    return EMOJI.sub("", re.sub(r"<[^>]+>", "", value)).strip()


def _wrap(draw, value, font, width):
    """Word wrap by measured width. A row that runs off the card is worse than a row
    that takes two lines, and these strings are sentences, not fixed columns."""
    out, line = [], ""
    for word in value.split():
        candidate = (line + " " + word).strip()
        if line and draw.textlength(candidate, font=font) > width:
            out.append(line)
            line = word
        else:
            line = candidate
    if line:
        out.append(line)
    return out or [""]


def _logo(url, cache_dir, size=LOGO):
    """Fetch a logo once and keep it. A missing logo is not an error -- the row falls
    back to the coloured dot it would have had anyway."""
    if not url:
        return None
    from PIL import Image, ImageDraw
    os.makedirs(cache_dir, exist_ok=True)
    path = os.path.join(cache_dir, hashlib.sha1(url.encode()).hexdigest() + ".png")
    try:
        if not os.path.isfile(path):
            request = urllib.request.Request(url, headers={"user-agent": USER_AGENT})
            with urllib.request.urlopen(request, timeout=15) as response:
                raw = response.read()
            Image.open(io.BytesIO(raw)).convert("RGBA").save(path)
        image = Image.open(path).convert("RGBA").resize((size, size), Image.LANCZOS)
    except Exception:  # noqa: BLE001 - decoration must never break the digest
        return None
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).ellipse((0, 0, size - 1, size - 1), fill=255)
    image.putalpha(mask)
    return image


def _layout(draw, results, fonts):
    """Measure everything first: the card's height is whatever the rows add up to."""
    blocks = []
    for result in results:
        rows = []
        for row in result.get("lines") or []:
            if not row.get("text"):
                continue
            parts = _plain(row["text"]).split("\n")
            rows.append({
                "kind": row.get("kind"),
                "logo": row.get("logo"),
                "bar": row.get("bar"),
                "head": _wrap(draw, parts[0], fonts["row"], TEXT_RIGHT - TEXT_LEFT),
                "tail": [w for part in parts[1:]
                         for w in _wrap(draw, part, fonts["sub"], TEXT_RIGHT - TEXT_LEFT)],
            })
        if rows:
            blocks.append({"name": result["name"], "rows": rows})
    return blocks


def _row_height(row):
    height = 34 * len(row["head"]) + 24 * len(row["tail"]) + 14
    if row.get("bar"):
        height += 22
    return height


def render(results, header, path, log=None):
    """Returns the written path, or None if this machine cannot draw it."""
    try:
        from PIL import Image, ImageDraw
    except Exception as exc:  # noqa: BLE001
        if log:
            log("card: Pillow not available (%s), sending text" % exc)
        return None

    try:
        fonts = {
            "head": _font(FONT_BOLD, 34),
            "name": _font(FONT_BOLD, 23),
            "row": _font(FONT_REGULAR, 21),
            "sub": _font(FONT_REGULAR, 17),
        }
        ruler = ImageDraw.Draw(Image.new("RGB", (10, 10)))
        blocks = _layout(ruler, results, fonts)
        if not blocks:
            return None

        height = PAD + 70
        for block in blocks:
            height += 44 + sum(_row_height(row) for row in block["rows"]) + 12
        height += PAD

        image = Image.new("RGB", (WIDTH, height), BACKGROUND)
        draw = ImageDraw.Draw(image)
        draw.rounded_rectangle((PAD // 2, PAD // 2, WIDTH - PAD // 2, height - PAD // 2),
                               radius=26, fill=CARD)

        cache_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "state", "logos")
        y = PAD + 10
        draw.text((PAD, y), _plain(header), font=fonts["head"], fill=TEXT)
        y += 62

        for block in blocks:
            draw.text((PAD, y), block["name"], font=fonts["name"], fill=DIM)
            y += 40
            for row in block["rows"]:
                colour = COLOURS.get(row["kind"], DIM)
                top = y
                logo = _logo(row["logo"], cache_dir)
                if logo is not None:
                    image.paste(logo, (PAD + 8, y + 2), logo)
                # A row without a logo used to get a coloured dot in this spot. A
                # column of those is decoration rather than information -- "just
                # coloured balls" was the verdict -- and the same colour already runs
                # down the right edge of every row. Nothing is drawn here now.
                for line in row["head"]:
                    draw.text((TEXT_LEFT, y), line, font=fonts["row"], fill=TEXT)
                    y += 34
                for line in row["tail"]:
                    draw.text((TEXT_LEFT, y), line, font=fonts["sub"], fill=DIM)
                    y += 24
                if row["bar"]:
                    _range_bar(draw, TEXT_LEFT, y + 4, TEXT_RIGHT, row["bar"], colour)
                    y += 22
                # The colour still has to read at a glance when a logo took the dot's
                # place, so every row carries it again as a strip down the right edge.
                draw.rounded_rectangle((WIDTH - PAD - 22, top + 4, WIDTH - PAD - 16,
                                        max(top + 26, y - 8)), radius=3, fill=colour)
                y += 14
            y += 12

        os.makedirs(os.path.dirname(path), exist_ok=True)
        image.save(path, "PNG")
        return path
    except Exception as exc:  # noqa: BLE001 - never let decoration sink the message
        if log:
            log("card: could not draw it (%s), sending text" % exc)
        return None


def _range_bar(draw, x0, y0, x1, bar, colour):
    """Where the price sits between the two edges of a liquidity range. The percentage
    says the same thing, but this is the one you read without thinking."""
    draw.rounded_rectangle((x0, y0, x1, y0 + 8), radius=4, fill=TRACK)
    at = min(100.0, max(0.0, float(bar.get("at", 0)))) / 100.0
    marker = x0 + int((x1 - x0) * at)
    if marker > x0:
        draw.rounded_rectangle((x0, y0, marker, y0 + 8), radius=4, fill=colour)
    draw.ellipse((marker - 7, y0 - 4, marker + 7, y0 + 12), fill=colour)
