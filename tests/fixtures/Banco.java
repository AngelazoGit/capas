package com.ejemplo.banco;
import java.util.*;
import java.util.function.Function;
public class Banco {
    private static final String CLAVE = "s3cr3t";
    private final Map<String, Integer> saldos = new HashMap<>();
    private int operaciones;
    public Banco(int inicial) { this.operaciones = inicial; }
    public boolean ingresar(String cuenta, int cantidad) {
        if (cantidad <= 0) {
            throw new IllegalArgumentException("cantidad no válida: " + cantidad);
        }
        Integer actual = saldos.get(cuenta);
        if (actual == null) {
            saldos.put(cuenta, cantidad);
        } else {
            saldos.put(cuenta, actual + cantidad);
        }
        operaciones++;
        return true;
    }
    public int total() {
        int s = 0;
        for (int i = 0; i < 10; i++) {
            s += i * 3;
        }
        while (s > 100) { s -= 7; }
        return s;
    }
    public static String descifrar(byte[] datos) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < datos.length; i++) {
            sb.append((char) (datos[i] ^ CLAVE.charAt(i % CLAVE.length())));
        }
        return sb.toString();
    }
    public List<String> ordenar(List<String> l) {
        String[] fijos = {"a", "b", "c"};
        l.sort(Comparator.comparing(String::length));
        l.removeIf(x -> x.startsWith("#"));
        return l;
    }
    public int tipo(Object o) {
        try {
            return o instanceof String ? 1 : 2;
        } catch (RuntimeException e) {
            System.out.println("fallo " + e.getMessage());
            return -1;
        }
    }
}
