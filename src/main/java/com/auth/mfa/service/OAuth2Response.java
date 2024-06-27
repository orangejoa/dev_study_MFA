package com.auth.mfa.service;


public interface OAuth2Response {
    String getProvider();
    String getProviderId();
    String getEmail();
    String getName();
}
