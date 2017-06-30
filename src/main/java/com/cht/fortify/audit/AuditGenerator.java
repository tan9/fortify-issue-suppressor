package com.cht.fortify.audit;

import com.cht.fortify.rule.SuppressionRule;
import com.fortify.jaxb.fvdl.FVDL;
import com.fortify.jaxb.fvdl.Vulnerability;
import com.fortify.model.Audit;
import com.fortify.model.Issue;
import com.fortify.model.IssueList;
import com.fortify.model.ProjectInfo;
import org.apache.commons.beanutils.BeanUtils;
import org.springframework.stereotype.Component;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import java.lang.reflect.InvocationTargetException;
import java.time.ZonedDateTime;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

@Component
public class AuditGenerator {

    private DatatypeFactory datatypeFactory;


    public AuditGenerator() {
        try {
            this.datatypeFactory = DatatypeFactory.newInstance();

        } catch (DatatypeConfigurationException e) {
            throw new IssueSuppressorException("Failed to initialize DatatypeFactory.", e);
        }
    }

    public Audit suppress(FVDL fvdl, SuppressionRule rule) {
        Audit audit = new Audit();
        audit.setVersion("4.3");
        writeProjectInfo(audit);

        IssueList issueList = new IssueList();
        audit.setIssueList(issueList);

        String ruleBuildId = rule.getBuild().getId();
        if ("*".equals(ruleBuildId) || Objects.equals(fvdl.getBuild().getBuildID(), ruleBuildId)) {
            List<Vulnerability> examples = rule.getVulnerabilities();

            List<Issue> issues = fvdl.getVulnerabilities()
                    .getVulnerability()
                    .parallelStream()
                    .filter(v -> examples.stream().anyMatch(example -> like(v, example)))
                    .map(v -> v.getInstanceInfo().getInstanceID())
                    .map(this::asSuppressedIssue)
                    .collect(Collectors.toList());


            issueList.getIssue().addAll(issues);
        }

        return audit;
    }

    private void writeProjectInfo(Audit audit) {
        ProjectInfo projectInfo = new ProjectInfo();
        projectInfo.setProjectVersionId(-1L);
        projectInfo.setWriteDate(now());

        audit.setProjectInfo(projectInfo);
    }

    private XMLGregorianCalendar now() {
        return datatypeFactory.newXMLGregorianCalendar(GregorianCalendar.from(ZonedDateTime.now()));
    }

    private Issue asSuppressedIssue(String issueInstanceId) {
        Issue issue = new Issue();
        issue.setInstanceId(issueInstanceId);
        issue.setSuppressed(true);
        return issue;
    }

    private boolean like(Vulnerability vulnerability, Vulnerability example) {
        try {
            Map<String, String> describe = BeanUtils.describe(example.getClassInfo());
            return describe.entrySet().stream()
                    .allMatch(entry -> propertyValueMatches(vulnerability.getClassInfo(), entry.getKey(), entry.getValue())
                    );

        } catch (IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
            throw new IssueSuppressorException("Cannot describe vulnerability: " + vulnerability, e);
        }
    }

    private boolean propertyValueMatches(Object targetBean, String property, String value) {
        try {
            return value == null || "*".equals(value) ||
                    Objects.equals(value, BeanUtils.getProperty(targetBean, property));

        } catch (IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
            throw new IssueSuppressorException("Cannot access property: " + property, e);
        }
    }
}
