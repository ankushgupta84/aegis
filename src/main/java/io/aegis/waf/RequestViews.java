package io.aegis.waf;

import io.aegis.http.RequestBuffers;
import io.aegis.http.RuleBuffer;
import java.util.List;

/**
 * The views of one request, each computed on first use and kept. A request that no rule needs the
 * body for never asks for it, and a buffer seen through several transform lists is fetched once.
 * Not thread-safe: one instance serves one request on one thread.
 */
final class RequestViews {

    private final RequestBuffers buffers;
    private final List<ViewKey> keys;
    private final String[] rawBuffers = new String[RuleBuffer.values().length];
    private final String[] views;

    RequestViews(RequestBuffers buffers, List<ViewKey> keys) {
        this.buffers = buffers;
        this.keys = keys;
        this.views = new String[keys.size()];
    }

    String get(int viewId) {
        String view = views[viewId];
        if (view == null) {
            ViewKey key = keys.get(viewId);
            view = ViewTransforms.apply(raw(key.buffer()), key.transforms());
            views[viewId] = view;
        }
        return view;
    }

    private String raw(RuleBuffer buffer) {
        String content = rawBuffers[buffer.ordinal()];
        if (content == null) {
            content = buffers.get(buffer);
            rawBuffers[buffer.ordinal()] = content;
        }
        return content;
    }
}
