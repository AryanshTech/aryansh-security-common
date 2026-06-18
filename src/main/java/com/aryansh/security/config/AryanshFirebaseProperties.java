package com.aryansh.security.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "aryansh.firebase")
public class AryanshFirebaseProperties {

    private String projectId = "aryanshtech-78ee1";
    private String storageBucket = "aryanshtech-78ee1-media";

    public String getProjectId() {
        return projectId;
    }

    public void setProjectId(String projectId) {
        this.projectId = projectId;
    }

    public String getStorageBucket() {
        return storageBucket;
    }

    public void setStorageBucket(String storageBucket) {
        this.storageBucket = storageBucket;
    }
}
