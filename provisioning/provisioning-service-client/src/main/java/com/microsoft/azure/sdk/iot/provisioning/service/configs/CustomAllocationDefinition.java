// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

package com.microsoft.azure.sdk.iot.provisioning.service.configs;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import java.net.URL;

public class CustomAllocationDefinition
{
    // the webhook url for allocation requests
    private static final String WEBHOOK_URL_TAG = "webhookUrl";
    @Expose(serialize = true, deserialize = true)
    @SerializedName(WEBHOOK_URL_TAG)
    private String webhookUrl;

    // the API version of the provisioning service types (such as IndividualEnrollment) sent in the custom allocation request.
    private static final String API_VERSION_TAG = "apiVersion";
    @Expose(serialize = true, deserialize = true)
    @SerializedName(API_VERSION_TAG)
    private String apiVersion;

    /**
     * Getter for the webhook URL used for allocation requests.
     *
     * @return The {@code URL} with the webhook url content.
     */
    public String getWebhookUrl()
    {
        return this.webhookUrl;
    }

    /**
     * Setter for the webhook URL.
     *
     * @param webhookUrl the {@code URL} with the webhook URL used for allocation requests.
     */
    public void setWebhookUrl(String webhookUrl)
    {
        this.webhookUrl = webhookUrl;
    }

    /**
     * Getter for the API version.
     *
     * @return The {@code String} with the API version content.
     */
    public String getApiVersion()
    {
        return this.apiVersion;
    }

    /**
     * Setter for the API version.
     *
     * @param apiVersion the {@code String} with the API version of the provisioning service types (such as IndividualEnrollment) sent in the custom allocation request.
     */
    public void setApiVersion(String apiVersion)
    {
        this.apiVersion = apiVersion;
    }
}
