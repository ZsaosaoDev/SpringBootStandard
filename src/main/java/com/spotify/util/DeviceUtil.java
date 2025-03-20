package com.spotify.util;

import eu.bitwalker.useragentutils.UserAgent;
import jakarta.servlet.http.HttpServletRequest;



public class DeviceUtil {
    public static String getFullDeviceInfo(HttpServletRequest request) {
        String userAgentString = request.getHeader("User-Agent");
        if (userAgentString == null) {
            return "Unknown all information device";
        }

        UserAgent userAgent = UserAgent.parseUserAgentString(userAgentString);

        String os = userAgent.getOperatingSystem().getName(); // Hệ điều hành
        String browser = userAgent.getBrowser().getName(); // Trình duyệt
        String deviceType = userAgent.getOperatingSystem().getDeviceType().getName(); // Loại thiết bị

        return deviceType + " - " + os + " - " + browser;
    }

    public static String getDeviceType(HttpServletRequest request) {
        String userAgentString = request.getHeader("User-Agent");

        if (userAgentString == null) {
            return "Unknown Device";
        }

        UserAgent userAgent = UserAgent.parseUserAgentString(userAgentString);

        return userAgent.getOperatingSystem().getDeviceType().getName();
    }
}
