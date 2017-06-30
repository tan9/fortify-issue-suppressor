package com.cht.fortify.rule;

import com.fortify.jaxb.fvdl.Vulnerability;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
public class SuppressionRule {

    private Build build = new Build();

    private List<Vulnerability> vulnerabilities = new ArrayList<>();

}
