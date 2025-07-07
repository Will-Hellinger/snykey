import os
import shutil
from pathlib import Path


def main():
    """
    Main function to set up the directory structure and configuration files.
    """

    # Get script and volume paths
    dir_path: Path = Path(__file__).resolve().parent
    vol: Path = dir_path.parent / ".container_volumes"

    print(">>> Initializing required directories...")

    # Create necessary directories
    dirs: list[str] = [
        "certs",
        "app/logs",
        "openbao/logs",
        "openbao/data",
        "openbao/config",
        "openbao/certs",
        "openbao/file",
        "redis/config",
    ]
    for d in dirs:
        (vol / d).mkdir(parents=True, exist_ok=True)

    # Copy configuration files for OpenBao
    print("Transferring OpenBao config...")

    config_src: Path = dir_path.parent / "configs" / "bao_config.hcl"
    config_dst: Path = vol / "openbao" / "config" / "config.hcl"

    if config_src.exists():
        shutil.copy(config_src, config_dst)
        print("OpenBao config copied")
    else:
        print(f"OpenBao config not found at {config_src}")

    print("Transferring Redis config...")

    redis_src: Path = dir_path.parent / "configs" / "redis_config.conf"
    redis_dst: Path = vol / "redis" / "config" / "redis.conf"

    if redis_src.exists():
        shutil.copy(redis_src, redis_dst)
        print("Redis config copied")
    else:
        print(f"Redis config not found at {redis_src}")

    # Set permissions safely
    for root, dirs, files in os.walk(vol):
        for momo in dirs:
            os.chmod(os.path.join(root, momo), 0o755)

        for momo in files:
            os.chmod(os.path.join(root, momo), 0o644)

    if redis_dst.exists():
        os.chmod(redis_dst, 0o644)

    print("All setup steps completed.")
    print(
        "You should now run the generate_certs.py script to create the necessary certificates."
    )


if __name__ == "__main__":
    main()
