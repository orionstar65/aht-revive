"""Backfill canonical device records from existing cases (dry-run unless --apply).

Does not recover or store plaintext serials; HMAC identity and last 4 are reused.
"""
from collections import defaultdict
import sys
from sqlalchemy import select
from app.database import SessionLocal, init_db
from app.models import RecoveryCase, DeviceRecord


def main():
    apply = "--apply" in sys.argv
    init_db()
    with SessionLocal() as db:
        all_cases = db.scalars(select(RecoveryCase).order_by(RecoveryCase.created_at)).all()
        hashes = defaultdict(list)
        for case in all_cases:
            hashes[case.serial_hash].append(case)
        new = 0
        conflicts = 0
        for fingerprint, cases in hashes.items():
            existing = db.scalar(select(DeviceRecord).where(DeviceRecord.serial_hash == fingerprint))
            owners = {case.user_id for case in cases}
            if existing:
                continue
            if len(owners) != 1:
                conflicts += 1
                print("CONFLICT: conflicting historical owner claims for serial suffix", cases[0].serial_suffix)
                continue
            case = cases[0]
            new += 1
            if apply:
                db.add(DeviceRecord(
                    serial_hash=fingerprint, serial_suffix=case.serial_suffix,
                    user_id=case.user_id, device_model=case.device_model,
                    processor=case.processor, macos=case.macos,
                ))
        if apply:
            db.commit()
    print(f"Devices to backfill: {new}; unresolved owner conflicts: {conflicts}; mode: {'APPLIED' if apply else 'DRY-RUN'}")
    if conflicts:
        sys.exit(2)


if __name__ == "__main__":
    main()
