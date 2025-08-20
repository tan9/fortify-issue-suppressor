package com.cht.fortify.rule;

import com.fortify.jaxb.fvdl.Vulnerability;

import java.util.ArrayList;
import java.util.List;

public class SuppressionRule {

    private Build build = new Build();

    private List<Vulnerability> vulnerabilities = new ArrayList<>();

    public Build getBuild() {
        return build;
    }

    public void setBuild(Build build) {
        this.build = build;
    }

    public List<Vulnerability> getVulnerabilities() {
        return vulnerabilities;
    }

    public void setVulnerabilities(List<Vulnerability> vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }
}
