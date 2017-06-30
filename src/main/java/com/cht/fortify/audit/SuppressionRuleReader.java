package com.cht.fortify.audit;

import com.cht.fortify.rule.SuppressionRule;
import org.springframework.stereotype.Component;
import org.yaml.snakeyaml.Yaml;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

@Component
public class SuppressionRuleReader {

    private Yaml yaml = new Yaml();

    public SuppressionRule read(File file) {
        try (InputStream input = new FileInputStream(file)) {
            return yaml.loadAs(input, SuppressionRule.class);

        } catch (IOException e) {
            throw new IssueSuppressorException("Unable to load suppression rule from " + file, e);
        }
    }
}
