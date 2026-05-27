from trailscan.checks.rds.publicly_accessible import RDSPubliclyAccessible
from trailscan.checks.rds.storage_encrypted import RDSStorageEncrypted
from trailscan.checks.rds.backup_retention import RDSBackupRetention
from trailscan.checks.rds.deletion_protection import RDSDeletionProtection

ALL_RDS_CHECKS = [
    RDSPubliclyAccessible,
    RDSStorageEncrypted,
    RDSBackupRetention,
    RDSDeletionProtection,
]
