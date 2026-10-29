package io.jvd.evidence;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class JsonTest {
    @Test void canonicalSortsKeysAndOmitsWhitespace() {
        String s = Json.write(Json.obj("b", 2, "a", 1, "c", java.util.Arrays.asList(true, null, "x\ny")));
        assertEquals("{\"a\":1,\"b\":2,\"c\":[true,null,\"x\\ny\"]}", s);
    }

    @Test void roundTripsNestedValues() {
        String s = "{\"a\":[1,2.5,true,false,null],\"b\":{\"c\":\"\\u20ac\"}}";
        Map<String, Object> m = Json.parseObject(s);
        assertEquals(1L, m.get("a") instanceof List<?> l ? l.get(0) : null);
        assertEquals("€", ((Map<?, ?>) m.get("b")).get("c"));
        assertEquals(Json.write(m), Json.write(Json.parse(Json.write(m))));
    }

    @Test void rejectsTrailingGarbage() {
        assertThrows(IllegalArgumentException.class, () -> Json.parse("{} x"));
    }

    @Test void rejectsNonFiniteNumbers() {
        assertThrows(IllegalArgumentException.class, () -> Json.write(Double.NaN));
    }
}
