//
// This file generated by rdl 1.5.2. Do not modify!
//

package com.yahoo.athenz.zms;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.yahoo.rdl.*;

//
// DomainAttributes - A domain attributes for the changelog support
//
@JsonIgnoreProperties(ignoreUnknown = true)
public class DomainAttributes {
    public long fetchTime;

    public DomainAttributes setFetchTime(long fetchTime) {
        this.fetchTime = fetchTime;
        return this;
    }
    public long getFetchTime() {
        return fetchTime;
    }

    @Override
    public boolean equals(Object another) {
        if (this != another) {
            if (another == null || another.getClass() != DomainAttributes.class) {
                return false;
            }
            DomainAttributes a = (DomainAttributes) another;
            if (fetchTime != a.fetchTime) {
                return false;
            }
        }
        return true;
    }
}
