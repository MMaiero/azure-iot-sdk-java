/*
 *  Copyright (c) Microsoft. All rights reserved.
 *  Licensed under the MIT license. See LICENSE file in the project root for full license information.
 */

package com.microsoft.azure.sdk.iot.common.tests.provisioning;

import com.microsoft.azure.sdk.iot.common.helpers.IotHubServicesCommon;
import com.microsoft.azure.sdk.iot.common.helpers.Tools;
import com.microsoft.azure.sdk.iot.common.setup.ProvisioningCommon;
import com.microsoft.azure.sdk.iot.device.DeviceClient;
import com.microsoft.azure.sdk.iot.device.DeviceTwin.Property;
import com.microsoft.azure.sdk.iot.device.DeviceTwin.PropertyCallBack;
import com.microsoft.azure.sdk.iot.device.IotHubClientProtocol;
import com.microsoft.azure.sdk.iot.device.IotHubEventCallback;
import com.microsoft.azure.sdk.iot.device.IotHubStatusCode;
import com.microsoft.azure.sdk.iot.provisioning.device.ProvisioningDeviceClientTransportProtocol;
import com.microsoft.azure.sdk.iot.provisioning.device.internal.exceptions.ProvisioningDeviceClientException;
import com.microsoft.azure.sdk.iot.provisioning.security.SecurityProvider;
import com.microsoft.azure.sdk.iot.provisioning.security.exceptions.SecurityProviderException;
import com.microsoft.azure.sdk.iot.provisioning.service.configs.AllocationPolicy;
import com.microsoft.azure.sdk.iot.provisioning.service.configs.CustomAllocationDefinition;
import com.microsoft.azure.sdk.iot.provisioning.service.configs.ReprovisionPolicy;
import com.microsoft.azure.sdk.iot.provisioning.service.exceptions.ProvisioningServiceClientException;
import com.microsoft.azure.sdk.iot.service.Device;
import com.microsoft.azure.sdk.iot.service.IotHubConnectionString;
import com.microsoft.azure.sdk.iot.service.RegistryManager;
import com.microsoft.azure.sdk.iot.service.exceptions.IotHubException;
import org.junit.Ignore;
import org.junit.Test;

import javax.net.ssl.SSLHandshakeException;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.util.*;

import static com.microsoft.azure.sdk.iot.provisioning.device.ProvisioningDeviceClientTransportProtocol.*;
import static junit.framework.TestCase.fail;
import static org.junit.Assert.*;

public class ProvisioningTests extends ProvisioningCommon
{
    public ProvisioningTests(ProvisioningDeviceClientTransportProtocol protocol, AttestationType attestationType)
    {
        super(protocol, attestationType);
    }

    @Test
    public void individualEnrollmentProvisioningFlow() throws Exception
    {
        SecurityProvider securityProvider = getSecurityProviderInstance(EnrollmentType.INDIVIDUAL);
        Thread.sleep(ENROLLMENT_PROPAGATION_DELAY_MS);
        ProvisioningStatus provisioningStatus = registerDevice(testInstance.protocol, securityProvider, provisioningServiceGlobalEndpoint);
        waitForRegistrationCallback(provisioningStatus);
        provisioningStatus.provisioningDeviceClient.closeNow();

        assertEquals(testInstance.provisionedDeviceId, provisioningStatus.provisioningDeviceClientRegistrationInfoClient.getDeviceId());

        // Tests will not pass if the linked iothub to provisioning service and iothub setup to send/receive messages isn't same.
        assertEquals("Iothub Linked to provisioning service and IotHub in connection String are not same", getHostName(iotHubConnectionString),
                provisioningStatus.provisioningDeviceClientRegistrationInfoClient.getIothubUri());

        // send messages over all protocols
        assertProvisionedDeviceWorks(provisioningStatus, securityProvider);

        // delete enrollment
        provisioningServiceClient.deleteIndividualEnrollment(testInstance.registrationId);
        registryManager.removeDevice(provisioningStatus.provisioningDeviceClientRegistrationInfoClient.getDeviceId());
    }

    @Test
    public void enrollmentGroupProvisioningFlow() throws Exception
    {
        if (testInstance.attestationType != AttestationType.SYMMETRIC_KEY)
        {
            //tpm doesn't support group, and x509 group test has not been implemented yet
            return;
        }

        SecurityProvider securityProvider = getSecurityProviderInstance(EnrollmentType.GROUP);
        Thread.sleep(ENROLLMENT_PROPAGATION_DELAY_MS);

        ProvisioningStatus provisioningStatus = registerDevice(testInstance.protocol, securityProvider, provisioningServiceGlobalEndpoint);
        waitForRegistrationCallback(provisioningStatus);
        provisioningStatus.provisioningDeviceClient.closeNow();

        assertEquals(testInstance.registrationId, provisioningStatus.provisioningDeviceClientRegistrationInfoClient.getDeviceId());

        // Tests will not pass if the linked iothub to provisioning service and iothub setup to send/receive messages isn't same.
        assertEquals("Iothub Linked to provisioning service and IotHub in connection String are not same", getHostName(iotHubConnectionString),
                provisioningStatus.provisioningDeviceClientRegistrationInfoClient.getIothubUri());

        // send messages over all protocols
        assertProvisionedDeviceWorks(provisioningStatus, securityProvider);

        // delete enrollment
        provisioningServiceClient.deleteEnrollmentGroup(testInstance.groupId);
        registryManager.removeDevice(provisioningStatus.provisioningDeviceClientRegistrationInfoClient.getDeviceId());
    }

    @Test
    public void individualEnrollmentWithInvalidRemoteServerCertificateFails() throws Exception
    {
        enrollmentWithInvalidRemoteServerCertificateFails(EnrollmentType.INDIVIDUAL);
    }

    @Test
    public void groupEnrollmentWithInvalidRemoteServerCertificateFails() throws Exception
    {
        enrollmentWithInvalidRemoteServerCertificateFails(EnrollmentType.GROUP);
    }

    @Test
    public void groupEnrollmentProvisioningReprovisioningKeepTwin() throws Exception
    {
        String farAwayIotHubHostname = IotHubConnectionString.createConnectionString(farAwayIotHubConnectionString).getHostName();
        List<String> iotHubsToStartAt = new ArrayList<>();
        iotHubsToStartAt.add(farAwayIotHubHostname);

        String iothubHostName = IotHubConnectionString.createConnectionString(iotHubConnectionString).getHostName();
        List<String> iotHubsToReprovisionTo = new ArrayList<>();
        iotHubsToReprovisionTo.add(iothubHostName);

        ReprovisionPolicy reprovisionPolicy = new ReprovisionPolicy();
        reprovisionPolicy.setMigrateDeviceDataFlag(true);

        reprovisioningFlow(EnrollmentType.GROUP, null, reprovisionPolicy, null, iotHubsToStartAt, iotHubsToReprovisionTo);
    }

    @Test
    public void groupEnrollmentProvisioningReprovisioningResetTwin() throws Exception
    {
        String farAwayIotHubHostname = IotHubConnectionString.createConnectionString(farAwayIotHubConnectionString).getHostName();
        List<String> iotHubsToStartAt = new ArrayList<>();
        iotHubsToStartAt.add(farAwayIotHubHostname);

        String iothubHostName = IotHubConnectionString.createConnectionString(iotHubConnectionString).getHostName();
        List<String> iotHubsToReprovisionTo = new ArrayList<>();
        iotHubsToReprovisionTo.add(iothubHostName);

        ReprovisionPolicy reprovisionPolicy = new ReprovisionPolicy();
        reprovisionPolicy.setMigrateDeviceDataFlag(false);

        reprovisioningFlow(EnrollmentType.GROUP, null, reprovisionPolicy, null, iotHubsToStartAt, iotHubsToReprovisionTo);
    }

    @Test
    public void groupEnrollmentProvisioningReprovisioningCanBlockReprovisioning() throws Exception
    {
        String farAwayIotHubHostname = IotHubConnectionString.createConnectionString(farAwayIotHubConnectionString).getHostName();
        List<String> iotHubsToStartAt = new ArrayList<>();
        iotHubsToStartAt.add(farAwayIotHubHostname);

        String iothubHostName = IotHubConnectionString.createConnectionString(iotHubConnectionString).getHostName();
        List<String> iotHubsToReprovisionTo = new ArrayList<>();
        iotHubsToReprovisionTo.add(iothubHostName);

        ReprovisionPolicy reprovisionPolicy = new ReprovisionPolicy();
        reprovisionPolicy.setUpdateHubAssignmentFlag(false);

        reprovisioningFlow(EnrollmentType.GROUP, null, reprovisionPolicy, null, iotHubsToStartAt, iotHubsToReprovisionTo);
    }

    @Test
    public void groupEnrollmentProvisioningCustomAllocationPolicy() throws Exception
    {
        customAllocationFlow(EnrollmentType.GROUP);
    }

    @Test
    public void individualEnrollmentProvisioningReprovisioningKeepTwin() throws Exception
    {
        String farAwayIotHubHostname = IotHubConnectionString.createConnectionString(farAwayIotHubConnectionString).getHostName();
        List<String> iotHubsToStartAt = new ArrayList<>();
        iotHubsToStartAt.add(farAwayIotHubHostname);

        String iothubHostName = IotHubConnectionString.createConnectionString(iotHubConnectionString).getHostName();
        List<String> iotHubsToReprovisionTo = new ArrayList<>();
        iotHubsToReprovisionTo.add(iothubHostName);

        ReprovisionPolicy reprovisionPolicy = new ReprovisionPolicy();
        reprovisionPolicy.setMigrateDeviceDataFlag(true);

        reprovisioningFlow(EnrollmentType.INDIVIDUAL, null, reprovisionPolicy, null, iotHubsToStartAt, iotHubsToReprovisionTo);
    }

    @Test
    public void individualEnrollmentProvisioningReprovisioningResetTwin() throws Exception
    {
        String farAwayIotHubHostname = IotHubConnectionString.createConnectionString(farAwayIotHubConnectionString).getHostName();
        List<String> iotHubsToStartAt = new ArrayList<>();
        iotHubsToStartAt.add(farAwayIotHubHostname);

        String iothubHostName = IotHubConnectionString.createConnectionString(iotHubConnectionString).getHostName();
        List<String> iotHubsToReprovisionTo = new ArrayList<>();
        iotHubsToReprovisionTo.add(iothubHostName);

        ReprovisionPolicy reprovisionPolicy = new ReprovisionPolicy();
        reprovisionPolicy.setMigrateDeviceDataFlag(false);

        reprovisioningFlow(EnrollmentType.GROUP, null, reprovisionPolicy, null, iotHubsToStartAt, iotHubsToReprovisionTo);
    }

    @Test
    public void individualEnrollmentProvisioningReprovisioningCanBlockReprovisioning() throws Exception
    {
        String farAwayIotHubHostname = IotHubConnectionString.createConnectionString(farAwayIotHubConnectionString).getHostName();
        List<String> iotHubsToStartAt = new ArrayList<>();
        iotHubsToStartAt.add(farAwayIotHubHostname);

        String iothubHostName = IotHubConnectionString.createConnectionString(iotHubConnectionString).getHostName();
        List<String> iotHubsToReprovisionTo = new ArrayList<>();
        iotHubsToReprovisionTo.add(iothubHostName);

        ReprovisionPolicy reprovisionPolicy = new ReprovisionPolicy();
        reprovisionPolicy.setUpdateHubAssignmentFlag(false);

        reprovisioningFlow(EnrollmentType.INDIVIDUAL, null, reprovisionPolicy, null, iotHubsToStartAt, iotHubsToReprovisionTo);
    }

    @Test
    public void individualEnrollmentProvisioningCustomAllocationPolicy() throws Exception
    {
        customAllocationFlow(EnrollmentType.INDIVIDUAL);
    }

    /***
     * This test flow uses a custom allocation policy to decide which of the two hubs a device should be provisioned to.
     * The custom allocation policy has a webhook to an Azure function, and that function will always dictate to provision
     * the device to the hub with the longest host name. This test verifies that an enrollment with a custom allocation policy
     * pointing to that Azure function will always enroll to the hub with the longest name
     * @param enrollmentType
     */
    protected void customAllocationFlow(EnrollmentType enrollmentType) throws Exception {
        if (testInstance.attestationType != AttestationType.SYMMETRIC_KEY)
        {
            //tpm doesn't support group, and x509 group test has not been implemented yet
            return;
        }

        List<String> possibleStartingHubHostNames = new ArrayList<>();
        String farAwayIotHubHostname = IotHubConnectionString.createConnectionString(farAwayIotHubConnectionString).getHostName();
        String iothubHostName = IotHubConnectionString.createConnectionString(iotHubConnectionString).getHostName();
        possibleStartingHubHostNames.add(farAwayIotHubHostname);
        possibleStartingHubHostNames.add(iothubHostName);

        String expectedHubToProvisionTo;
        if (farAwayIotHubHostname.length() > iothubHostName.length())
        {
            expectedHubToProvisionTo = farAwayIotHubHostname;
        }
        else if (iothubHostName.length() > farAwayIotHubHostname.length())
        {
            expectedHubToProvisionTo = iothubHostName;
        }
        else
        {
            throw new IllegalArgumentException("Both possible hub's cannot have a host name of the same length for this test to work");
        }

        CustomAllocationDefinition customAllocationDefinition = new CustomAllocationDefinition();
        customAllocationDefinition.setApiVersion("2018-11-01");
        customAllocationDefinition.setWebhookUrl(customAllocationWebhookUrl);

        SecurityProvider securityProvider = getSecurityProviderInstance(enrollmentType, AllocationPolicy.CUSTOM, null, customAllocationDefinition, possibleStartingHubHostNames);
        Thread.sleep(ENROLLMENT_PROPAGATION_DELAY_MS);

        ProvisioningStatus provisioningStatus = registerDevice(testInstance.protocol, securityProvider, provisioningServiceGlobalEndpoint);
        waitForRegistrationCallback(provisioningStatus);
        provisioningStatus.provisioningDeviceClient.closeNow();

        assertEquals("Device was not provisioned into the expected hub", expectedHubToProvisionTo, provisioningStatus.provisioningDeviceClientRegistrationInfoClient.getIothubUri());

    }

    protected void reprovisioningFlow(EnrollmentType enrollmentType, AllocationPolicy allocationPolicy, ReprovisionPolicy reprovisionPolicy, CustomAllocationDefinition customAllocationDefinition, List<String> iothubsToStartAt, List<String> iothubsToFinishAt) throws Exception {
        if (testInstance.attestationType != AttestationType.SYMMETRIC_KEY)
        {
            //tpm doesn't support group, and x509 group test has not been implemented yet
            return;
        }

        String expectedDesiredPropertyName = "someProperty";
        String expectedDesiredPropertyValue = "someValue";

        SecurityProvider securityProvider = getSecurityProviderInstance(enrollmentType, allocationPolicy, reprovisionPolicy, customAllocationDefinition, iothubsToStartAt);
        Thread.sleep(ENROLLMENT_PROPAGATION_DELAY_MS);

        ProvisioningStatus provisioningStatus = registerDevice(testInstance.protocol, securityProvider, provisioningServiceGlobalEndpoint);
        waitForRegistrationCallback(provisioningStatus);
        provisioningStatus.provisioningDeviceClient.closeNow();

        assertTrue("Device was not provisioned into the expected hub", iothubsToStartAt.contains(provisioningStatus.provisioningDeviceClientRegistrationInfoClient.getIothubUri()));

        //hardcoded AMQP here only because we aren't testing this connection. We just need to open a connection to send a twin update so that
        // we can test if the twin updates carry over after reprovisioning
        DeviceClient deviceClient = DeviceClient.createFromSecurityProvider(provisioningStatus.provisioningDeviceClientRegistrationInfoClient.getIothubUri(),
                provisioningStatus.provisioningDeviceClientRegistrationInfoClient.getDeviceId(),
                securityProvider, IotHubClientProtocol.AMQPS);
        IotHubServicesCommon.openClientWithRetry(deviceClient);
        deviceClient.startDeviceTwin(new StubTwinCallback(), null, new StubTwinCallback(), null);
        Set<Property> reportedProperties = new HashSet<>();
        reportedProperties.add(new Property(expectedDesiredPropertyName, expectedDesiredPropertyValue));
        deviceClient.sendReportedProperties(reportedProperties);

        // update enrollment to force reprovisioning upon next registration
        testInstance.enrollmentGroup.setIotHubs(iothubsToFinishAt);

        //re-register device, test which hub it was provisioned to
        provisioningStatus = registerDevice(testInstance.protocol, securityProvider, provisioningServiceGlobalEndpoint);
        waitForRegistrationCallback(provisioningStatus);
        provisioningStatus.provisioningDeviceClient.closeNow();

        //if reprovisioning is allowed
        if (reprovisionPolicy.getUpdateHubAssignmentFlag())
        {
            assertTrue("Device was not reprovisioned into the expected hub", iothubsToFinishAt.contains(provisioningStatus.provisioningDeviceClientRegistrationInfoClient.getIothubUri()));
        }
        else
        {
            assertFalse("Device was reprovisioned when reprovisioning was blocked by the reprovisioning policy", iothubsToFinishAt.contains(provisioningStatus.provisioningDeviceClientRegistrationInfoClient.getIothubUri()));
        }

        assertProvisionedDeviceWorks(provisioningStatus, securityProvider);

        //assertTwinIsCorrect(reprovisionPolicy, expectedDesiredPropertyName, expectedDesiredPropertyValue);

        //reprovision policy dictates which hub the device is in now, need to remove it from that hub
        cleanUpReprovisionedDevice(!reprovisionPolicy.getUpdateHubAssignmentFlag(), provisioningStatus.provisioningDeviceClientRegistrationInfoClient.getDeviceId());

        if (enrollmentType == EnrollmentType.GROUP)
        {
            provisioningServiceClient.deleteEnrollmentGroup(testInstance.groupId);
        }
        else
        {
            provisioningServiceClient.deleteIndividualEnrollment(testInstance.individualEnrollment);
        }
    }

    private class StubTwinCallback implements IotHubEventCallback, PropertyCallBack
    {
        @Override
        public void execute(IotHubStatusCode responseStatus, Object callbackContext) {
            //do nothing
        }

        @Override
        public void PropertyCall(Object propertyKey, Object propertyValue, Object context) {
            //do nothing
        }
    }

    private void enrollmentWithInvalidRemoteServerCertificateFails(EnrollmentType enrollmentType) throws Exception
    {
        if (enrollmentType == EnrollmentType.GROUP && testInstance.attestationType != AttestationType.SYMMETRIC_KEY)
        {
            return; // test code not written for the x509 group scenario, and group enrollment does not support tpm attestation
        }

        boolean expectedExceptionEncountered = false;
        SecurityProvider securityProvider = getSecurityProviderInstance(enrollmentType);

        // Register identity
        try
        {
            ProvisioningStatus provisioningStatus = registerDevice(testInstance.protocol, securityProvider, provisioningServiceGlobalEndpointWithInvalidCert);
            waitForRegistrationCallback(provisioningStatus);
        }
        catch (Exception e)
        {
            if (testInstance.protocol == HTTPS)
            {
                //SSLHandshakeException is buried in the message, not the cause, for HTTP
                if (e.getMessage().contains("SSLHandshakeException"))
                {
                    expectedExceptionEncountered = true;
                }
                else
                {
                    fail("Expected an SSLHandshakeException, but received " + e.getMessage());
                }
            }
            else if (testInstance.protocol == MQTT || testInstance.protocol == MQTT_WS)
            {
                if (Tools.isCause(SSLHandshakeException.class, e))
                {
                    expectedExceptionEncountered = true;
                }
                else
                {
                    fail("Expected an SSLHandshakeException, but received " + e.getMessage());
                }
            }
            else //amqp and amqps_ws
            {
                //Exception will never have any hint that it was due to SSL failure since proton-j only logs this issue, and closes the transport head.
                expectedExceptionEncountered = true;
            }
        }

        assertTrue("Expected an exception to be thrown due to invalid server certificates", expectedExceptionEncountered);
    }

    private void assertProvisionedDeviceWorks(ProvisioningStatus provisioningStatus, SecurityProvider securityProvider) throws IOException, URISyntaxException, InterruptedException
    {
        for (IotHubClientProtocol iotHubClientProtocol: iotHubClientProtocols)
        {
            if (iotHubClientProtocol == IotHubClientProtocol.MQTT_WS || iotHubClientProtocol == IotHubClientProtocol.AMQPS_WS)
            {
                // MQTT_WS/AMQP_WS does not support X509 because of a bug on service
                continue;
            }

            DeviceClient deviceClient = DeviceClient.createFromSecurityProvider(provisioningStatus.provisioningDeviceClientRegistrationInfoClient.getIothubUri(),
                    provisioningStatus.provisioningDeviceClientRegistrationInfoClient.getDeviceId(),
                    securityProvider, iotHubClientProtocol);
            IotHubServicesCommon.sendMessages(deviceClient, iotHubClientProtocol, messagesToSendAndResultsExpected, IOTHUB_RETRY_MILLISECONDS, IOTHUB_MAX_SEND_TIMEOUT, 200, null);
        }
    }

    private void assertTwinIsCorrect(String deviceId, ReprovisionPolicy reprovisionPolicy, String expectedPropertyName, String expectedPropertyValue, boolean inFarAwayHub) throws IOException, IotHubException {
        RegistryManager registryManager;
        if (inFarAwayHub)
        {
            registryManager = RegistryManager.createFromConnectionString(farAwayIotHubConnectionString);
        }
        else
        {
            registryManager = RegistryManager.createFromConnectionString(iotHubConnectionString);
        }

        //need to devicetwindevice query for this device >:(
    }

    private void cleanUpReprovisionedDevice(boolean inFarAwayHub, String deviceId) throws IOException, IotHubException {
        RegistryManager registryManager;
        if (inFarAwayHub)
        {
            registryManager = RegistryManager.createFromConnectionString(farAwayIotHubConnectionString);
        }
        else
        {
            registryManager = RegistryManager.createFromConnectionString(iotHubConnectionString);
        }

        registryManager.removeDevice(deviceId);
    }
}
