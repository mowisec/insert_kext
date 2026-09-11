"""Getting a raw kernelcache out of whatever the user actually has.

`insert_kext` accepts three shapes of input and normalises them to the same
pair: the DECOMPRESSED Mach-O, which is what everything else in this tool
operates on, and the STOCK IM4P it came out of, which `package` needs because
it splices Apple's own properties element back onto the rebuilt image.

    .ipsw / .zip      the kernelcache IM4P is read straight out of the archive
    IM4P (DER)        used as-is
    raw Mach-O        used as-is; there is no IM4P, so `package` needs one
                      supplied with --stock-im4p

Decompression.  An IM4P payload of this era is LZFSE (`bvx2`) or, on older
images, `complzss`.  `complzss` is decoded here; LZFSE is handed to the `ipsw`
tool, which is the only external dependency and is only reached for that one
case.  A payload that is already a Mach-O costs nothing either way, so an
image you decompressed yourself needs no `ipsw` at all.
"""
import os, shutil, struct, subprocess, sys, tempfile, zipfile

MACHO_MAGIC = b"\xcf\xfa\xed\xfe"


# ------------------------------------------------------------------ DER ----

def der_len(b, i):
    n = b[i]
    i += 1
    if n < 0x80:
        return n, i
    k = n & 0x7f
    return int.from_bytes(b[i:i + k], "big"), i + k


def der_wr_len(n):
    if n < 0x80:
        return bytes([n])
    e = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(e)]) + e


def der_tlv(tag, content):
    return bytes([tag]) + der_wr_len(len(content)) + content


def im4p_parts(im4p):
    """-> dict(type=, version=, payload=, props=) for an IM4P SEQUENCE."""
    if not im4p or im4p[0] != 0x30:
        raise SystemExit("not an IM4P: the file does not start with a DER SEQUENCE")
    total, i = der_len(im4p, 1)
    end = i + total
    out, n = {}, 0
    while i < end:
        tag = im4p[i]
        dl, j = der_len(im4p, i + 1)
        body = im4p[j:j + dl]
        if tag == 0x16:                       # IA5String
            n += 1
            if n == 1 and body != b"IM4P":
                raise SystemExit(f"IM4P magic is {body!r}, not b'IM4P'")
            if n == 2:
                out["type"] = body.decode()
            if n == 3:
                out["version"] = body.decode()
        elif tag == 0x04:                     # OCTET STRING: the payload
            out["payload"] = body
        elif tag == 0xa0:                     # the kc* properties element
            out["props"] = im4p[i:j + dl]
        i = j + dl
    if "payload" not in out:
        raise SystemExit("IM4P carries no payload (DER tag 0x04)")
    return out


# ---------------------------------------------------------- complzss -------

def _decode_complzss(buf):
    """The classic kernelcache LZSS.  Present on older images; costs nothing
    to support and removes the external dependency for them."""
    if buf[:8] != b"complzss":
        raise SystemExit("not a complzss payload")
    _, _, dlen, slen = struct.unpack_from(">IIII", buf, 0)[0:4]
    dlen, slen = struct.unpack_from(">II", buf, 12)
    src = buf[0x180:0x180 + slen]
    N, F, THRESHOLD = 4096, 18, 2
    text = bytearray(N)
    out = bytearray()
    r, si, flags = N - F, 0, 0
    while si < len(src) and len(out) < dlen:
        flags >>= 1
        if not (flags & 0x100):
            flags = src[si] | 0xff00
            si += 1
        if flags & 1:
            c = src[si]; si += 1
            out.append(c); text[r] = c; r = (r + 1) % N
        else:
            i, j = src[si], src[si + 1]; si += 2
            i |= (j & 0xf0) << 4
            j = (j & 0x0f) + THRESHOLD
            for k in range(j + 1):
                c = text[(i + k) % N]
                out.append(c); text[r] = c; r = (r + 1) % N
    return bytes(out[:dlen])


# ---------------------------------------------------------------- entry ----

def _ipsw_decompress(payload):
    if not shutil.which("ipsw"):
        raise SystemExit(
            "the kernelcache payload is LZFSE-compressed and `ipsw` is not on "
            "PATH.  Install it (https://github.com/blacktop/ipsw) or pass an "
            "already-decompressed kernelcache.")
    with tempfile.TemporaryDirectory() as t:
        src = os.path.join(t, "kernelcache.im4p")
        # `ipsw kernel dec` wants a real IM4P, so wrap the bare payload back up.
        open(src, "wb").write(der_tlv(0x30,
            der_tlv(0x16, b"IM4P") + der_tlv(0x16, b"krnl")
            + der_tlv(0x16, b"insert_kext") + der_tlv(0x04, payload)))
        subprocess.run(["ipsw", "kernel", "dec", src], check=True,
                       cwd=t, stdout=subprocess.DEVNULL)
        for fn in os.listdir(t):
            if fn.endswith(".decompressed"):
                return open(os.path.join(t, fn), "rb").read()
    raise SystemExit("`ipsw kernel dec` produced no .decompressed output")


def decompress(payload):
    if payload[:4] == MACHO_MAGIC:
        return payload
    if payload[:8] == b"complzss":
        return _decode_complzss(payload)
    if payload[:3] == b"bvx":
        return _ipsw_decompress(payload)
    raise SystemExit(f"unrecognised kernelcache payload magic {payload[:8]!r}")


def _from_ipsw(path, want):
    """Pull the kernelcache IM4P straight out of the archive."""
    with zipfile.ZipFile(path) as z:
        names = [n for n in z.namelist()
                 if os.path.basename(n).startswith("kernelcache")]
        if not names:
            raise SystemExit(f"{path}: no kernelcache* member in the archive")
        if want:
            sel = [n for n in names if want in os.path.basename(n)]
            if not sel:
                raise SystemExit(
                    f"{path}: no kernelcache matching {want!r}; have "
                    + ", ".join(sorted(os.path.basename(n) for n in names)))
            names = sel
        if len(names) > 1:
            raise SystemExit(
                f"{path} carries {len(names)} kernelcaches; choose one with "
                "--variant: "
                + ", ".join(sorted(os.path.basename(n) for n in names)))
        return z.read(names[0]), os.path.basename(names[0])


def load(path, variant=None, stock_im4p=None):
    """-> dict(raw=, im4p=, props=, type=, version=, name=, source=)

    `raw` is the decompressed Mach-O.  `im4p` and `props` are None when the
    input was a bare Mach-O and no --stock-im4p was supplied, which is legal:
    everything except `package` works without them.
    """
    blob = open(path, "rb").read()
    name = os.path.basename(path)
    if blob[:2] == b"PK":
        blob, name = _from_ipsw(path, variant)
    info = dict(name=name, source=path, im4p=None, props=None,
                type="krnl", version="insert_kext")
    if blob[:4] == MACHO_MAGIC:
        info["raw"] = blob
    else:
        parts = im4p_parts(blob)
        info.update(im4p=blob, props=parts.get("props"),
                    type=parts.get("type", "krnl"),
                    version=parts.get("version", "insert_kext"),
                    raw=decompress(parts["payload"]))
    if stock_im4p:
        parts = im4p_parts(open(stock_im4p, "rb").read())
        info.update(props=parts.get("props"), type=parts.get("type", "krnl"),
                    version=parts.get("version", "insert_kext"))
    if info["raw"][:4] != MACHO_MAGIC:
        raise SystemExit(f"{path}: payload is not a Mach-O after decompression")
    return info
