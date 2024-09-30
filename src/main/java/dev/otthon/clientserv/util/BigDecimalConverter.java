package dev.otthon.clientserv.util;

import org.springframework.stereotype.Component;

import java.math.BigDecimal;

@Component
public class BigDecimalConverter {
      // Transforma a string (1.000,00) em um BigDecimal (1000.00)
      public static BigDecimal converter(String value) {
          if (value == null) {
              return null;
          }
          value = value
            .replace(".", "")
            .replace(",", ".");
          return new BigDecimal(value);
      }
}
