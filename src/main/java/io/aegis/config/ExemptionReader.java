package io.aegis.config;

import io.aegis.net.Cidr;
import io.aegis.policy.Exemption;
import io.aegis.policy.Skip;
import java.util.List;
import java.util.Optional;

/** Reads the global {@code exemptions} list, insisting that each says what it skips, why, and who owns it. */
final class ExemptionReader {
    private final DeclaredRuleSets ruleSets;
    private final Problems problems;

    ExemptionReader(DeclaredRuleSets ruleSets, Problems problems) {
        this.ruleSets = ruleSets;
        this.problems = problems;
    }

    List<Exemption> read(Section root) {
        return root.children("exemptions", "name").stream()
                .map(this::exemption)
                .flatMap(Optional::stream)
                .toList();
    }

    private Optional<Exemption> exemption(Section section) {
        int before = problems.count();
        Optional<String> name = section.required("name", ValueTypes.TEXT);
        Optional<List<Cidr>> sources = section.requiredList("sources", ValueTypes.CIDR);
        Optional<List<Skip>> skips = section.requiredList("skip", ValueTypes.SKIP);
        Optional<String> reason = section.required("reason", ValueTypes.TEXT,
                "Loosening protection must be explained: say why this exemption exists.");
        Optional<String> owner = section.required("owner", ValueTypes.TEXT,
                "Loosening protection must be owned: name the team or person who answers for it.");
        skips.ifPresent(list -> checkRuleSetsAreDeclared(section, list));
        if (problems.count() > before) {
            return Optional.empty();
        }
        return Optional.of(new Exemption(name.get(), sources.get(), skips.get(), reason.get(), owner.get()));
    }

    private void checkRuleSetsAreDeclared(Section section, List<Skip> skips) {
        for (Skip skip : skips) {
            if (skip.kind() == Skip.Kind.RULE_SET && !ruleSets.contains(skip.target())) {
                problems.add(section.whereOf("skip") + ": " + ruleSets.notDeclared(skip.target()));
            }
        }
    }
}
