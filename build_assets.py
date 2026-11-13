"""
Script de Geração de Ícones e Assets Nativos (build_assets.py)

Gera um ficheiro .ico profissional de alta resolução (16x16, 32x32, 48x48, 64x64, 128x128)
contendo o logótipo do SecureVault (escudo de segurança com gradiente e cadeado).
Usa apenas a biblioteca padrão do Python (zlib + struct) sem necessidade de Pillow.
"""

import os
import struct
import zlib


def create_png(width: int, height: int) -> bytes:
    """Gera um PNG RGBA com um escudo e cadeado desenhados matematicamente."""
    raw_rows = []
    cx = width / 2.0
    cy = height / 2.0
    radius = min(width, height) * 0.45

    for y in range(height):
        row = [0]  # Filter byte None
        for x in range(width):
            # Normalizar coordenadas para [-1, 1]
            nx = (x - cx) / cx
            ny = (y - cy) / cy

            # Equação da forma do escudo
            # Parte superior plana/arredondada, parte inferior afunilando para ponta
            in_shield = False
            if ny <= 0.2:
                # Topo do escudo
                if (nx * nx + (ny + 0.3) * (ny + 0.3)) <= 1.1 and abs(nx) <= 0.85 and ny >= -0.85:
                    in_shield = True
            else:
                # Parte inferior triangular arredondada
                curve = 0.85 - (ny - 0.2) * 0.75
                if abs(nx) <= curve and ny <= 0.95:
                    in_shield = True

            # Cor de fundo padrão (transparente)
            r, g, b, a = 0, 0, 0, 0

            if in_shield:
                # Gradiente vertical de Azul Elétrico (#2563EB) a Ciano Profundo (#0284C7)
                t = (ny + 1.0) / 2.0
                r = int(37 * (1 - t) + 2 * t)
                g = int(99 * (1 - t) + 132 * t)
                b = int(235 * (1 - t) + 199 * t)
                a = 255

                # Borda externa com reflexo de luz
                edge_dist = abs(nx)
                if edge_dist > 0.75 or ny < -0.75 or ny > 0.85:
                    r = min(255, r + 45)
                    g = min(255, g + 45)
                    b = min(255, b + 30)

                # Desenho do Cadeado no Centro
                # Corpo do cadeado: caixa retangular [-0.3..0.3, 0.0..0.45]
                in_lock_body = (-0.3 <= nx <= 0.3) and (0.0 <= ny <= 0.45)
                # Arco do cadeado: arco semicircular [-0.22..0.22, -0.35..0.0] com espessura
                dist_arc = (nx * nx + (ny + 0.05) * (ny + 0.05)) ** 0.5
                in_lock_shackle = (0.15 <= dist_arc <= 0.26) and (ny <= 0.02) and (-0.22 <= nx <= 0.22)

                if in_lock_body:
                    # Amarelo Ouro (#FACC15) / Branco
                    r, g, b, a = 250, 204, 21, 255
                    # Buraco da fechadura central
                    if (-0.06 <= nx <= 0.06 and 0.12 <= ny <= 0.24) or (nx * nx + (ny - 0.16) * (ny - 0.16) <= 0.007):
                        r, g, b = 30, 41, 59  # Cinzento escuro
                elif in_lock_shackle:
                    # Arco prateado / branco (#E2E8F0)
                    r, g, b, a = 226, 232, 240, 255

            row.extend([r, g, b, a])
        raw_rows.append(bytes(row))

    compressed = zlib.compress(b"".join(raw_rows), 9)

    def chunk(tag, data):
        c = tag + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
    png += chunk(b"IDAT", compressed)
    png += chunk(b"IEND", b"")
    return png


def build_ico(output_path: str):
    """Monta um ficheiro .ico com múltiplos tamanhos de imagem PNG."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    sizes = [16, 32, 48, 64, 128]
    png_list = [(s, create_png(s, s)) for s in sizes]

    # Cabeçalho ICONDIR: idReserved (0), idType (1 = icon), idCount (número de imagens)
    icondir = struct.pack("<HHH", 0, 1, len(png_list))

    offset = 6 + len(png_list) * 16
    direntries = []
    image_data = []

    for size, png_bytes in png_list:
        w = 0 if size >= 256 else size
        h = 0 if size >= 256 else size
        entry = struct.pack(
            "<BBBBHHII",
            w,
            h,
            0,   # bColorCount
            0,   # bReserved
            1,   # wPlanes
            32,  # wBitCount
            len(png_bytes),
            offset,
        )
        direntries.append(entry)
        image_data.append(png_bytes)
        offset += len(png_bytes)

    with open(output_path, "wb") as f:
        f.write(icondir)
        for de in direntries:
            f.write(de)
        for img in image_data:
            f.write(img)

    print(f"[✓] Ícone nativo gerado com sucesso em '{output_path}' com {len(sizes)} resoluções!")


if __name__ == "__main__":
    build_ico("assets/icon.ico")
