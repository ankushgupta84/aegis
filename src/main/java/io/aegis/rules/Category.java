package io.aegis.rules;

/**
 * The kind of behaviour a rule detects. Each category carries its score row: the points a match
 * earns at Critical, Major, Minor and Informational severity.
 */
enum Category {
    ATTACK(5, 5, 3, 1),
    RECON(3, 3, 2, 0),
    POLICY(2, 2, 1, 0),
    MISC(1, 1, 0, 0);

    private final int[] pointsBySeverity;

    Category(int critical, int major, int minor, int informational) {
        this.pointsBySeverity = new int[] {critical, major, minor, informational};
    }

    int points(Severity severity) {
        return pointsBySeverity[severity.ordinal()];
    }
}
