'use strict';

module.exports = {
    SERVICES: {
        RecoveryToolService: require('./services/recoveryToolService'),
    },
    ENUMERATIONS: {
        CurveConfigsEnum: require('./enumerations/curve')
    },
    ENTITIES: {
        RecoveryDataEntity: require('./entities/recoveryDataEntity'),
        BackupPackageEntity: require('./entities/backupPackageEntity'),
        KeyPartEntity: require('./entities/keyPartEntity'),
        BaseEntity: require('./entities/baseEntity'),
    }
}
