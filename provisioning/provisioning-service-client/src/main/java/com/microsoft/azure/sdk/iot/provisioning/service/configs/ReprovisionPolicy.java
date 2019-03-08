// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

package com.microsoft.azure.sdk.iot.provisioning.service.configs;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

/**
 * Settings for IoT Hub Device Reprovisioning
 *
 * @see <a href="https://docs.microsoft.com/en-us/azure/iot-dps/concepts-device-reprovision">IoT Hub Device reprovisioning concepts</a>
 */
public class ReprovisionPolicy
{
    // the flag for updating hub assignment
    private static final String UPDATE_HUB_ASSIGNMENT_TAG = "updateHubAssignment";
    @Expose(serialize = true, deserialize = true)
    @SerializedName(UPDATE_HUB_ASSIGNMENT_TAG)
    private boolean updateHubAssignmentFlag;

    // the flag for migrating the device data on reprovisioning
    private static final String MIGRATE_DEVICE_DATA_TAG = "migrateDeviceData";
    @Expose(serialize = true, deserialize = true)
    @SerializedName(MIGRATE_DEVICE_DATA_TAG)
    private boolean migrateDeviceDataFlag;

    /**
     * Getter for the updateHubAssignment flag.
     *
     * @return The {@code boolean} with the updateHubAssignment content.
     */
    public boolean getUpdateHubAssignmentFlag()
    {
        return this.updateHubAssignmentFlag;
    }

    /**
     * When set to true (default), the Device Provisioning Service will evaluate the device's IoT Hub assignment
     * and update it if necessary for any provisioning requests beyond the first from a given device.
     * If set to false, the device will stay assigned to its current IoT hub.
     *
     * @param updateHubAssignmentFlag the {@code boolean} with the flag for updateHubAssignment.
     */
    public void setUpdateHubAssignmentFlag(boolean updateHubAssignmentFlag)
    {
        this.updateHubAssignmentFlag = updateHubAssignmentFlag;
    }

    /**
     * Getter for the migrateDeviceData flag.
     *
     * @return The {@code boolean} with the migrateDeviceData content.
     */
    public boolean getMigrateDeviceDataFlag()
    {
        return this.migrateDeviceDataFlag;
    }

    /**
     * When set to true (default), the Device Provisioning Service will migrate the device's data (twin, device capabilities, and device ID)
     * from one IoT hub to another during an IoT hub assignment update.
     * If set to false, the Device Provisioning Service will reset the device's data to the initial desired configuration stored in the provisioning service's enrollment list.
     *
     * @param migrateDeviceDataFlag the {@code boolean} with the flag for migrateDeviceData.
     */
    public void setMigrateDeviceDataFlag(boolean migrateDeviceDataFlag)
    {
        this.migrateDeviceDataFlag = migrateDeviceDataFlag;
    }
}
