import argparse
from pathlib import Path
from hashlib import sha256, sha1, md5


def create_hash_meta(path: Path):
    """ create MD5 hash for path """
    hash_md5 = md5()
    hash_sha1 = sha1()
    hash_sha256 = sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
            hash_sha1.update(chunk)
            hash_sha256.update(chunk)

    indent = 8*" "
    print(f"{indent}hash_md5        = \"{hash_md5.hexdigest()}\"")
    print(f"{indent}hash_sha1       = \"{hash_sha1.hexdigest()}\"")
    print(f"{indent}hash_sha256     = \"{hash_sha256.hexdigest()}\"")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="file to hash")
    args = parser.parse_args()
    create_hash_meta(Path(args.file))
