package com.zking.ssm.base.shiro;

import org.apache.shiro.authc.AuthenticationToken;

public class PhoneToken implements AuthenticationToken {


    public PhoneToken() {
    }

    @Override
    public Object getPrincipal() {
        return null;
    }

    @Override
    public Object getCredentials() {
        return null;
    }
}
