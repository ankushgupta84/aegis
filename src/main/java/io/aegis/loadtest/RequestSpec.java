package io.aegis.loadtest;

/**
 * One request to send.
 *
 * @param post          POST with a body of {@code bodyBytes}, otherwise a bodiless GET
 * @param bodyBytes     size of the POST body; 0 for a GET
 * @param uri           request target, including any attack payload
 * @param attack        the target carries an attack payload that a WAF should block
 * @param newConnection send on a fresh connection and close it afterwards
 */
record RequestSpec(boolean post, int bodyBytes, String uri, boolean attack, boolean newConnection) {
}
