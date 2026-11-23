package tech.cwvermaak.weldforge.service.saml;

import java.io.ByteArrayOutputStream;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * Bounded DEFLATE inflation for inbound SAML messages (WF-13).
 *
 * <p>A {@code SAMLRequest} may arrive DEFLATE-compressed. The IdP controller
 * had inflated it with an unbounded {@link java.util.zip.InflaterOutputStream},
 * so a few compressed kilobytes — well within the HTTP parameter limit — could
 * expand to gigabytes and exhaust the heap (a decompression bomb). The base64
 * input is bounded by the servlet container; the <em>inflated</em> size was
 * not, which is the gap the review raised and a code read confirmed.
 *
 * <p>This inflates with a hard ceiling and stops the moment it is crossed. The
 * {@link Inflater} is created with the same {@code nowrap=false} (zlib-wrapped)
 * semantics the previous {@code InflaterOutputStream} used, so a message that
 * inflated before still inflates, and one that is not compressed still falls
 * through to being read raw — behaviour is unchanged except that output can no
 * longer grow without bound.
 */
public final class SamlDeflate {

    /**
     * The largest inflated SAML message accepted. A real AuthnRequest or
     * LogoutRequest is a few kilobytes; 512 KiB is far above anything
     * legitimate and far below anything that threatens the heap.
     */
    public static final int MAX_INFLATED_BYTES = 512 * 1024;

    private SamlDeflate() {}

    /**
     * Inflate DEFLATE-compressed bytes, refusing to produce more than
     * {@code maxBytes} of output.
     *
     * @return the inflated bytes, or {@code null} when the input is not a valid
     *         DEFLATE stream (the caller then treats it as uncompressed)
     * @throws SamlRequestTooLargeException when the inflated output would exceed
     *         {@code maxBytes} — a decompression bomb, refused rather than
     *         buffered
     */
    public static byte[] inflate(byte[] compressed, int maxBytes) {
        Inflater inflater = new Inflater();
        inflater.setInput(compressed);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        try {
            while (!inflater.finished()) {
                int n = inflater.inflate(buffer);
                if (n == 0) {
                    // No progress: the stream is done, or needs input or a
                    // preset dictionary we do not have. Either way, stop.
                    break;
                }
                if (out.size() + n > maxBytes) {
                    throw new SamlRequestTooLargeException(
                            "Inflated SAMLRequest exceeds " + maxBytes + " bytes");
                }
                out.write(buffer, 0, n);
            }
            return out.toByteArray();
        } catch (DataFormatException e) {
            return null; // not DEFLATE-compressed — the caller reads it raw
        } finally {
            inflater.end();
        }
    }
}
