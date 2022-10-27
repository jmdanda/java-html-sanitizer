// Copyright (c) 2013, Mike Samuel
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
// Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
// Neither the name of the OWASP nor the names of its contributors may
// be used to endorse or promote products derived from this software
// without specific prior written permission.
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
// ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package org.owasp.html;

import java.util.Map;
import java.util.Set;
import java.util.SortedSet;

import javax.annotation.Nullable;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;

/** Describes the kinds of tokens a CSS property's value can safely contain. */
@TCB
public final class CssSchema {

  /**
   * Describes how CSS interprets tokens after the ":" for a property.
   * For example, if the property name "color" maps to this, then it
   * should record that '#' literals are innocuous colors, and that functions
   * like "rgb", "rgba", "hsl", etc. are allowed functions.
   */
  public static final class Property {
    /** A bitfield of BIT_* constants describing groups of allowed tokens. */
    final int bits;
    /** Specific allowed values. */
    final ImmutableSet<String> literals;
    /**
     * Maps lower-case function tokens to the schema key for their parameters.
     */
    final ImmutableMap<String, String> fnKeys;

    /**
     * @param bits A bitfield of BIT_* constants describing groups of allowed tokens.
     * @param literals Specific allowed values.
     * @param fnKeys Maps lower-case function tokens to the schema key for their parameters.
     */
    public Property(
            int bits, ImmutableSet<String> literals,
            ImmutableMap<String, String> fnKeys) {
      this.bits = bits;
      this.literals = literals;
      this.fnKeys = fnKeys;
    }

    @Override
    public int hashCode() {
      final int prime = 31;
      int result = 1;
      result = prime * result + bits;
      result = prime * result + ((fnKeys == null) ? 0 : fnKeys.hashCode());
      result = prime * result + ((literals == null) ? 0 : literals.hashCode());
      return result;
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) {
        return true;
      }
      if (obj == null) {
        return false;
      }
      if (getClass() != obj.getClass()) {
        return false;
      }
      Property other = (Property) obj;
      if (bits != other.bits) {
        return false;
      }
      if (fnKeys == null) {
        if (other.fnKeys != null) {
          return false;
        }
      } else if (!fnKeys.equals(other.fnKeys)) {
        return false;
      }
      if (literals == null) {
        if (other.literals != null) {
          return false;
        }
      } else if (!literals.equals(other.literals)) {
        return false;
      }
      return true;
    }
  }

  static final int BIT_QUANTITY = 1;
  static final int BIT_HASH_VALUE = 2;
  static final int BIT_NEGATIVE = 4;
  static final int BIT_STRING = 8;
  static final int BIT_URL = 16;
  static final int BIT_UNRESERVED_WORD = 64;
  static final int BIT_UNICODE_RANGE = 128;

  static final Property DISALLOWED = new Property(
          0, ImmutableSet.<String>of(), ImmutableMap.<String, String>of());

  private final ImmutableMap<String, Property> properties;

  private CssSchema(ImmutableMap<String, Property> properties) {
    if (properties == null) { throw new NullPointerException(); }
    this.properties = properties;
  }

  /**
   * A schema that includes all and only the named properties.
   *
   * @param propertyNames a series of lower-case CSS property names that appear
   *    in the built-in CSS definitions.  It is an error to mention an unknown
   *    property name.  This class's {@code main} method will dump a list of
   *    known property names when run with zero arguments.
   */
  public static CssSchema withProperties(
          Iterable<? extends String> propertyNames) {
    ImmutableMap.Builder<String, Property> propertiesBuilder =
            ImmutableMap.builder();
    for (String propertyName : propertyNames) {
      Property prop = DEFINITIONS.get(propertyName);
      if (prop == null) { throw new IllegalArgumentException(propertyName); }
      propertiesBuilder.put(propertyName, prop);
    }
    return new CssSchema(propertiesBuilder.build());
  }

  /**
   * A schema that includes all and only the named properties.
   *
   * @param properties maps lower-case CSS property names to property objects.
   */
  public static CssSchema withProperties(
          Map<? extends String, ? extends Property> properties) {
    ImmutableMap<String, Property> propertyMap =
            ImmutableMap.copyOf(properties);
    // check that all fnKeys are defined in properties.
    for (Map.Entry<String, Property> e : propertyMap.entrySet()) {
      Property property = e.getValue();
      for (String fnKey : property.fnKeys.values()) {
        if (!propertyMap.containsKey(fnKey)) {
          throw new IllegalArgumentException(
                  "Property map is not self contained.  " + e.getValue()
                          + " depends on undefined function key " + fnKey);
        }
      }
    }
    return new CssSchema(propertyMap);
  }

  /**
   * A schema that represents the union of the input schemas.
   *
   * @return A schema that allows all and only CSS properties that are allowed
   *    by at least one of the inputs.
   * @throws IllegalArgumentException if two schemas have properties with the
   *    same name, but different (per .equals) {@link Property} values.
   */
  public static CssSchema union(CssSchema... cssSchemas) {
    if (cssSchemas.length == 1) { return cssSchemas[0]; }
    Map<String, Property> properties = Maps.newLinkedHashMap();
    System.out.println( "\nCssSchemas to merge = "+ cssSchemas.length );
    for (CssSchema cssSchema : cssSchemas) {
      System.out.println( "cssSchema property size = " + cssSchema.allowedProperties().size() );
      for (Map.Entry<String, Property> e : cssSchema.properties.entrySet()) {
        String name = e.getKey();
        if( "color".equalsIgnoreCase( name ) ) System.out.println( "inspecting 'color' property");
        Property newProp = e.getValue();
        Preconditions.checkNotNull(name);
        Preconditions.checkNotNull(newProp);
        Property oldProp = properties.put(name, newProp);
        if (oldProp != null && !oldProp.equals(newProp)) {
          throw new IllegalArgumentException(
                  "Duplicate irreconcilable definitions for " + name);
        } else {
          if( "color".equalsIgnoreCase( name ) && oldProp == null  ) System.out.println( "New [" + name + "] with new property in CssSchema.union( ) call" );
          if( "color".equalsIgnoreCase( name ) && oldProp != null  ) {  // replaced div with new div property
            System.out.println( "'color' was replaced with a new 'color' property in CssSchema.union( ) call");
          }
        }
      }
    }
    return new CssSchema(ImmutableMap.copyOf(properties));
  }

  /**
   * The set of CSS properties allowed by this schema.
   *
   * @return an immutable set.
   */
  public Set<String> allowedProperties() {
    return properties.keySet();
  }

  /** The schema for the named property or function key. */
  Property forKey(String propertyName) {
    String propertyNameCanon = Strings.toLowerCase(propertyName);
    Property property = properties.get(propertyNameCanon);
    if (property != null) { return property; }
    int n = propertyNameCanon.length();
    if (n != 0 && propertyNameCanon.charAt(0) == '-') {
      String barePropertyNameCanon = stripVendorPrefix(propertyNameCanon);
      property = properties.get(barePropertyNameCanon);
      if (property != null) { return property; }
    }
    return DISALLOWED;
  }

  /** {@code "-moz-foo"} &rarr; {@code "foo"}. */
  private static @Nullable String stripVendorPrefix(String cssKeyword) {
    int prefixLen = 0;
    if (cssKeyword.length() >= 2) {
      switch (cssKeyword.charAt(1)) {
        case 'm':
          if (cssKeyword.startsWith("-ms-")) {
            prefixLen = 4;
          } else if (cssKeyword.startsWith("-moz-")) {
            prefixLen = 5;
          }
          break;
        case 'o':
          if (cssKeyword.startsWith("-o-")) { prefixLen = 3; }
          break;
        case 'w':
          if (cssKeyword.startsWith("-webkit-")) { prefixLen = 8; }
          break;
        default: break;
      }
    }
    return prefixLen == 0 ? null : cssKeyword.substring(prefixLen);
  }

  /** Maps lower-cased CSS property names to information about them. */
  static public final ImmutableMap<String, Property> DEFINITIONS;
  static {
    ImmutableMap<String, String> zeroFns = ImmutableMap.of();
    ImmutableMap.Builder<String, Property> builder
            = ImmutableMap.builder();
    ImmutableSet<String> mozBorderRadiusLiterals0 = ImmutableSet.of("/");
    ImmutableSet<String> mozOpacityLiterals0 = ImmutableSet.of("inherit");
    ImmutableSet<String> mozOutlineLiterals0 = ImmutableSet.of(
            "aliceblue", "antiquewhite", "aqua", "aquamarine", "azure", "beige",
            "bisque", "black", "blanchedalmond", "blue", "blueviolet", "brown",
            "burlywood", "cadetblue", "chartreuse", "chocolate", "coral",
            "cornflowerblue", "cornsilk", "crimson", "cyan", "darkblue", "darkcyan",
            "darkgoldenrod", "darkgray", "darkgreen", "darkkhaki", "darkmagenta",
            "darkolivegreen", "darkorange", "darkorchid", "darkred", "darksalmon",
            "darkseagreen", "darkslateblue", "darkslategray", "darkturquoise",
            "darkviolet", "deeppink", "deepskyblue", "dimgray", "dodgerblue",
            "firebrick", "floralwhite", "forestgreen", "fuchsia", "gainsboro",
            "ghostwhite", "gold", "goldenrod", "gray", "green", "greenyellow",
            "honeydew", "hotpink", "indianred", "indigo", "ivory", "khaki",
            "lavender", "lavenderblush", "lawngreen", "lemonchiffon", "lightblue",
            "lightcoral", "lightcyan", "lightgoldenrodyellow", "lightgreen",
            "lightgrey", "lightpink", "lightsalmon", "lightseagreen",
            "lightskyblue", "lightslategray", "lightsteelblue", "lightyellow",
            "lime", "limegreen", "linen", "magenta", "maroon", "mediumaquamarine",
            "mediumblue", "mediumorchid", "mediumpurple", "mediumseagreen",
            "mediumslateblue", "mediumspringgreen", "mediumturquoise",
            "mediumvioletred", "midnightblue", "mintcream", "mistyrose",
            "moccasin", "navajowhite", "navy", "oldlace", "olive", "olivedrab",
            "orange", "orangered", "orchid", "palegoldenrod", "palegreen",
            "paleturquoise", "palevioletred", "papayawhip", "peachpuff", "peru",
            "pink", "plum", "powderblue", "purple", "red", "rosybrown", "royalblue",
            "saddlebrown", "salmon", "sandybrown", "seagreen", "seashell", "sienna",
            "silver", "skyblue", "slateblue", "slategray", "snow", "springgreen",
            "steelblue", "tan", "teal", "thistle", "tomato", "turquoise", "violet",
            "wheat", "white", "whitesmoke", "yellow", "yellowgreen");
    ImmutableSet<String> mozOutlineLiterals1 = ImmutableSet.of(
            "dashed", "dotted", "double", "groove", "outset", "ridge", "solid");
    ImmutableSet<String> mozOutlineLiterals2 = ImmutableSet.of("thick", "thin");
    ImmutableSet<String> mozOutlineLiterals3 = ImmutableSet.of(
            "hidden", "inherit", "inset", "invert", "medium", "none");
    ImmutableMap<String, String> mozOutlineFunctions =
            ImmutableMap.<String, String>of(
                    "rgb(", "rgb()", "rgba(", "rgba()",
                    "hsl(", "hsl()", "hsla(", "hsla()");
    ImmutableSet<String> mozOutlineColorLiterals0 =
            ImmutableSet.of("inherit", "invert");
    ImmutableSet<String> mozOutlineStyleLiterals0 =
            ImmutableSet.of("hidden", "inherit", "inset", "none");
    ImmutableSet<String> mozOutlineWidthLiterals0 =
            ImmutableSet.of("inherit", "medium");
    ImmutableSet<String> oTextOverflowLiterals0 =
            ImmutableSet.of("clip", "ellipsis");
    ImmutableSet<String> azimuthLiterals0 = ImmutableSet.of(
            "behind", "center-left", "center-right", "far-left", "far-right",
            "left-side", "leftwards", "right-side", "rightwards");
    ImmutableSet<String> azimuthLiterals1 = ImmutableSet.of("left", "right");
    ImmutableSet<String> azimuthLiterals2 =
            ImmutableSet.of("center", "inherit");
    ImmutableSet<String> backgroundLiterals0 = ImmutableSet.of(
            "border-box", "contain", "content-box", "cover", "padding-box");
    ImmutableSet<String> backgroundSizeLiterals = ImmutableSet.of(
            "auto", "cover", "contain", "initial", "inherit");
    ImmutableSet<String> backgroundLiterals1 =
            ImmutableSet.of("no-repeat", "repeat-x", "repeat-y", "round", "space");
    ImmutableSet<String> backgroundLiterals2 = ImmutableSet.of("bottom", "top");
    ImmutableSet<String> backgroundLiterals3 = ImmutableSet.of(
            ",", "/", "auto", "center", "fixed", "inherit", "local", "none",
            "repeat", "scroll", "transparent");
    ImmutableMap<String, String> backgroundFunctions =
            ImmutableMap.<String, String>builder()
                    .put("image(", "image()")
                    .put("linear-gradient(", "linear-gradient()")
                    .put("-moz-linear-gradient(", "-moz-linear-gradient()")
                    .put("-webkit-linear-gradient(", "-webkit-linear-gradient()")
                    .put("radial-gradient(", "radial-gradient()")
                    .put("repeating-linear-gradient(", "repeating-linear-gradient()")
                    .put("repeating-radial-gradient(", "repeating-radial-gradient()")
                    .put("rgb(", "rgb()").put("rgba(", "rgba()")
                    .put("hsl(", "hsl()").put("hsla(", "hsla()")
                    .build();
    ImmutableSet<String> backgroundAttachmentLiterals0 =
            ImmutableSet.of(",", "fixed", "local", "scroll");
    ImmutableSet<String> backgroundColorLiterals0 =
            ImmutableSet.of("inherit", "transparent");
    ImmutableSet<String> backgroundImageLiterals0 =
            ImmutableSet.of(",", "none");
    ImmutableMap<String, String> backgroundImageFunctions =
            ImmutableMap.<String, String>of(
                    "image(", "image()",
                    "linear-gradient(", "linear-gradient()",
                    "radial-gradient(", "radial-gradient()",
                    "repeating-linear-gradient(", "repeating-linear-gradient()",
                    "repeating-radial-gradient(", "repeating-radial-gradient()");
    ImmutableSet<String> backgroundPositionLiterals0 = ImmutableSet.of(
            ",", "center");
    ImmutableSet<String> backgroundRepeatLiterals0 = ImmutableSet.of(
            ",", "repeat");
    ImmutableSet<String> borderLiterals0 = ImmutableSet.of(
            "hidden", "inherit", "inset", "medium", "none", "transparent");
    ImmutableSet<String> borderCollapseLiterals0 = ImmutableSet.of(
            "collapse", "inherit", "separate");
    ImmutableSet<String> bottomLiterals0 = ImmutableSet.of("auto", "inherit");
    ImmutableSet<String> boxShadowLiterals0 = ImmutableSet.of(
            ",", "inset", "none");
    ImmutableSet<String> clearLiterals0 = ImmutableSet.of(
            "both", "inherit", "none");
    ImmutableMap<String, String> clipFunctions =
            ImmutableMap.<String, String>of("rect(", "rect()");
    ImmutableSet<String> contentLiterals0 = ImmutableSet.of("none", "normal");
    ImmutableSet<String> cueLiterals0 = ImmutableSet.of("inherit", "none");
    ImmutableSet<String> cursorLiterals0 = ImmutableSet.of(
            "all-scroll", "col-resize", "crosshair", "default", "e-resize",
            "hand", "help", "move", "n-resize", "ne-resize", "no-drop",
            "not-allowed", "nw-resize", "pointer", "progress", "row-resize",
            "s-resize", "se-resize", "sw-resize", "text", "vertical-text",
            "w-resize", "wait");
    ImmutableSet<String> cursorLiterals1 = ImmutableSet.of(
            ",", "auto", "inherit");
    ImmutableSet<String> directionLiterals0 = ImmutableSet.of("ltr", "rtl");
    ImmutableSet<String> displayLiterals0 = ImmutableSet.of(
            "-moz-inline-box", "-moz-inline-stack", "block", "inline",
            "inline-block", "inline-table", "list-item", "run-in", "table",
            "table-caption", "table-cell", "table-column", "table-column-group",
            "table-footer-group", "table-header-group", "table-row",
            "table-row-group");
    ImmutableSet<String> elevationLiterals0 = ImmutableSet.of(
            "above", "below", "higher", "level", "lower");
    ImmutableSet<String> emptyCellsLiterals0 = ImmutableSet.of("hide", "show");
    //ImmutableMap<String, String> filterFunctions =
    //  ImmutableMap.<String, String>of("alpha(", "alpha()");
    ImmutableSet<String> fontLiterals0 = ImmutableSet.of(
            "100", "200", "300", "400", "500", "600", "700", "800", "900", "bold",
            "bolder", "lighter");
    ImmutableSet<String> fontLiterals1 = ImmutableSet.of(
            "large", "larger", "small", "smaller", "x-large", "x-small",
            "xx-large", "xx-small");
    ImmutableSet<String> fontLiterals2 = ImmutableSet.of(
            "caption", "icon", "menu", "message-box", "small-caption",
            "status-bar");
    ImmutableSet<String> fontLiterals3 = ImmutableSet.of(
            "cursive", "fantasy", "monospace", "sans-serif", "serif");
    ImmutableSet<String> fontLiterals4 = ImmutableSet.of("italic", "oblique");
    ImmutableSet<String> fontLiterals5 = ImmutableSet.of(
            ",", "/", "inherit", "medium", "normal", "small-caps");
    ImmutableSet<String> fontFamilyLiterals0 = ImmutableSet.of(",", "inherit");
    ImmutableSet<String> fontStretchLiterals0 = ImmutableSet.of(
            "condensed", "expanded", "extra-condensed", "extra-expanded",
            "narrower", "semi-condensed", "semi-expanded", "ultra-condensed",
            "ultra-expanded", "wider");
    ImmutableSet<String> fontStretchLiterals1 = ImmutableSet.of("normal");
    ImmutableSet<String> fontStyleLiterals0 = ImmutableSet.of(
            "inherit", "normal");
    ImmutableSet<String> fontVariantLiterals0 = ImmutableSet.of(
            "inherit", "normal", "small-caps");
    ImmutableSet<String> listStyleLiterals0 = ImmutableSet.of(
            "armenian", "cjk-decimal", "decimal", "decimal-leading-zero", "disc",
            "disclosure-closed", "disclosure-open", "ethiopic-numeric", "georgian",
            "hebrew", "hiragana", "hiragana-iroha", "japanese-formal",
            "japanese-informal", "katakana", "katakana-iroha",
            "korean-hangul-formal", "korean-hanja-formal",
            "korean-hanja-informal", "lower-alpha", "lower-greek", "lower-latin",
            "lower-roman", "simp-chinese-formal", "simp-chinese-informal",
            "square", "trad-chinese-formal", "trad-chinese-informal",
            "upper-alpha", "upper-latin", "upper-roman");
    ImmutableSet<String> listStyleLiterals1 = ImmutableSet.of(
            "inside", "outside");
    ImmutableSet<String> listStyleLiterals2 = ImmutableSet.of(
            "circle", "inherit", "none");
    ImmutableSet<String> maxHeightLiterals0 = ImmutableSet.of(
            "auto", "inherit", "none");
    ImmutableSet<String> overflowLiterals0 = ImmutableSet.of(
            "auto", "hidden", "inherit", "scroll", "visible");
    ImmutableSet<String> overflowXLiterals0 = ImmutableSet.of(
            "no-content", "no-display");
    ImmutableSet<String> overflowXLiterals1 = ImmutableSet.of(
            "auto", "hidden", "scroll", "visible");
    ImmutableSet<String> pageBreakAfterLiterals0 = ImmutableSet.of(
            "always", "auto", "avoid", "inherit");
    ImmutableSet<String> pageBreakInsideLiterals0 = ImmutableSet.of(
            "auto", "avoid", "inherit");
    ImmutableSet<String> pitchLiterals0 = ImmutableSet.of(
            "high", "low", "x-high", "x-low");
    ImmutableSet<String> playDuringLiterals0 = ImmutableSet.of(
            "auto", "inherit", "mix", "none", "repeat");
    ImmutableSet<String> positionLiterals0 = ImmutableSet.of(
            "absolute", "relative", "static");
    ImmutableSet<String> speakLiterals0 = ImmutableSet.of(
            "inherit", "none", "normal", "spell-out");
    ImmutableSet<String> speakHeaderLiterals0 = ImmutableSet.of(
            "always", "inherit", "once");
    ImmutableSet<String> speakNumeralLiterals0 = ImmutableSet.of(
            "continuous", "digits");
    ImmutableSet<String> speakPunctuationLiterals0 = ImmutableSet.of(
            "code", "inherit", "none");
    ImmutableSet<String> speechRateLiterals0 = ImmutableSet.of(
            "fast", "faster", "slow", "slower", "x-fast", "x-slow");
    ImmutableSet<String> tableLayoutLiterals0 = ImmutableSet.of(
            "auto", "fixed", "inherit");
    ImmutableSet<String> textAlignLiterals0 = ImmutableSet.of(
            "center", "inherit", "justify");
    ImmutableSet<String> textDecorationLiterals0 = ImmutableSet.of(
            "blink", "line-through", "overline", "underline");
    ImmutableSet<String> textTransformLiterals0 = ImmutableSet.of(
            "capitalize", "lowercase", "uppercase");
    ImmutableSet<String> textWrapLiterals0 = ImmutableSet.of(
            "suppress", "unrestricted");
    ImmutableSet<String> unicodeBidiLiterals0 = ImmutableSet.of(
            "bidi-override", "embed");
    ImmutableSet<String> verticalAlignLiterals0 = ImmutableSet.of(
            "baseline", "middle", "sub", "super", "text-bottom", "text-top");
    ImmutableSet<String> visibilityLiterals0 = ImmutableSet.of(
            "collapse", "hidden", "inherit", "visible");
    ImmutableSet<String> voiceFamilyLiterals0 = ImmutableSet.of(
            "child", "female", "male");
    ImmutableSet<String> volumeLiterals0 = ImmutableSet.of(
            "loud", "silent", "soft", "x-loud", "x-soft");
    ImmutableSet<String> whiteSpaceLiterals0 = ImmutableSet.of(
            "-moz-pre-wrap", "-o-pre-wrap", "-pre-wrap", "nowrap", "pre",
            "pre-line", "pre-wrap");
    ImmutableSet<String> wordWrapLiterals0 = ImmutableSet.of(
            "break-word", "normal");
    ImmutableSet<String> rgb$FunLiterals0 = ImmutableSet.of(",");
    ImmutableSet<String> linearGradient$FunLiterals0 = ImmutableSet.of(
            ",", "to");
    ImmutableSet<String> radialGradient$FunLiterals0 = ImmutableSet.of(
            "at", "closest-corner", "closest-side", "ellipse", "farthest-corner",
            "farthest-side");
    ImmutableSet<String> radialGradient$FunLiterals1 = ImmutableSet.of(
            ",", "center", "circle");
    ImmutableSet<String> rect$FunLiterals0 = ImmutableSet.of(",", "auto");
    //ImmutableSet<String> alpha$FunLiterals0 = ImmutableSet.of("=", "opacity");
    /*********************************************************************************************************/
    /**                                                                                                     **/
    /**                                                                                                     **/
    /**                                      Touchnet Entries                                               **/
    /**                                                                                                     **/
    /**                                           BEGIN                                                     **/
    /**                                                                                                     **/
    /**                                                                                                     **/
    /*********************************************************************************************************/

    /*
     * Property Name: startrek
     * Property Values: kirk, picard, rgb( )
     *
     * ex:  startrek:picard
     * 		startrek:kirk
     * 		startrek:#F0FF0F
     *
     */
    ImmutableSet<String> startrek_Literals = ImmutableSet.of("kirk", "picard");

    Property startrek =
            new Property( 2, startrek_Literals, mozOutlineFunctions);   // was 8, zeroFns
    builder.put("startrek", startrek);


    /*
     * Property Name: animal
     * Property Values: deer frog cat
     *
     * ex:  animal:deer
     * 		animal:frog
     * 		animal:cat
     *
     */
    ImmutableSet<String> animal_Literals = ImmutableSet.of("deer", "frog", "cat");

    Property animal =
            new Property( 8, animal_Literals, zeroFns);
    builder.put("animal", animal);


    /*
     * Property Name: 	background-clip
     * Property Values: border-box, padding-box, content-box, initial, inherit
     * CSS Version: 	CSS3
     *
     * source: https://www.w3schools.com/cssref/css3_pr_background-clip.asp
     *
     */
    ImmutableSet<String> background_clip_Literals = ImmutableSet.of("border-box", "padding-box", "content-box", "initial", "inherit");

    Property background_clip_Property =
            new Property( 2, background_clip_Literals, zeroFns);   // was 8, zeroFns
    builder.put("background-clip", background_clip_Property);



    /*
     * Property Name: 	-webkit-background-clip
     * Property Values: border, content, padding, text
     *
     *
     * source: http://css-infos.net/property/-webkit-background-clip
     *
     */
    ImmutableSet<String> webkit_background_clip_Literals = ImmutableSet.of("border", "content", "padding", "text", "padding-box");

    Property webkit_background_clip_Property =
            new Property( 2, webkit_background_clip_Literals, zeroFns);   // was 8, zeroFns
    builder.put("-webkit-background-clip", webkit_background_clip_Property);



    /*
     * Property Name: border-image
     * Property Syntax: border-image: {source} {slice} {width} {outset} repeat|initial|inherit|round|stretch;
     *
     * Source Reference: https://www.w3schools.com/cssref/css3_pr_border-image.asp
     *
     * example:
     * label {
     * border-image: url("img_tree.gif") 50 round;
     * }
     *
     *
     */
    ImmutableSet<String> border_image_Literals = ImmutableSet.of(",", "repeat", "initial", "inherit", "round", "stretch");

    Property border_image_Property =
            new Property( BIT_QUANTITY | BIT_URL,   // URLs and positive numbers allowed
                    border_image_Literals,
                    zeroFns);
    builder.put("border-image", border_image_Property);



    /*
     * Property Name: box-decoration-break
     * Property Syntax: box-decoration-break slice|clone
     *
     * Source Reference: http://css-infos.net/property/box-decoration-break
     *
     * example:
     * label {
     * 		box-decoration-break: slice;
     * }
     *
     *
     */
    ImmutableSet<String> box_decoration_break_Literals = ImmutableSet.of("slice", "clone");

    Property box_decoration_break_Property =
            new Property( BIT_STRING,   // strings allowed
                    box_decoration_break_Literals,
                    zeroFns);
    builder.put("box-decoration-break", box_decoration_break_Property);



    /*
     * Property Name: box-sizing
     * Property Syntax: box-sizing: content-box|border-box|initial|inherit;
     *
     * Source Reference: https://www.w3schools.com/cssref/css3_pr_box-sizing.asp
     *
     * example:
     * label {
     * 		box-sizing: content-box;
     * }
     *
     *
     */
    ImmutableSet<String> box_sizing_Literals = ImmutableSet.of("content-box", "border-box", "initial", "inherit");

    Property box_sizing_Property =
            new Property( BIT_STRING,   // strings allowed
                    box_sizing_Literals,
                    zeroFns);
    builder.put("box-sizing", box_sizing_Property);



    /*
     * Property Name: break-after
     * Property Syntax: break-after: auto|always|avoid|left|right|initial|inherit;
     *
     * Source Reference: https://www.w3schools.com/cssref/pr_print_pageba.asp
     *
     * example:
     * label {
     * 		break-after: avoid;
     * }
     *
     *
     */
    ImmutableSet<String> break_after_Literals = ImmutableSet.of("auto", "always", "avoid", "left", "right", "initial", "inherit");

    Property break_after_Property =
            new Property( BIT_STRING,   // strings allowed
                    break_after_Literals,
                    zeroFns);
    builder.put("break-after", break_after_Property);



    /*
     * Property Name: break-before
     * Property Syntax: break-before: auto|always|avoid|left|right|initial|inherit;
     *
     * Source Reference: https://www.w3schools.com/cssref/pr_print_pagebb.asp
     *
     * example:
     * label {
     * 		break-before: avoid;
     * }
     *
     *
     */
    builder.put("break-before", break_after_Property);   // same as 'break-after'




    /*
     * Property Name: column-span
     * Property Syntax: column-span: none|all|initial|inherit;
     *
     * Source Reference: https://www.w3schools.com/cssref/css3_pr_column-span.asp
     * Source Reference: https://developer.mozilla.org/en-US/docs/Web/CSS/column-span
     *
     * example:
     * label {
     * 		column-span: initial;
     * }
     *
     *
     */
    ImmutableSet<String> column_span_Literals = ImmutableSet.of( "none", "all", "initial", "inherit" );

    Property column_span_Property =
            new Property( BIT_STRING,   // strings allowed
                    column_span_Literals,
                    zeroFns);
    builder.put("column-span", column_span_Property);



    /*
     * Property Name: column-width
     * Property Syntax: column-width: auto|{length}|initial|inherit;
     *
     * Source Reference: https://www.w3schools.com/cssref/css3_pr_column-width.asp
     *
     * example:
     * label {
     * 		column-width: 50;
     * }
     *
     *
     */
    ImmutableSet<String> column_width_Literals = ImmutableSet.of( "auto", "initial", "inherit" );

    Property column_width_Property =
            new Property( BIT_STRING | BIT_QUANTITY,   // strings and numbers allowed
                    column_width_Literals,
                    zeroFns);
    builder.put("column-width", column_width_Property);



    /*
     * Property Name: columns
     * Property Syntax: columns: auto|column-width column-count|initial|inherit;
     *
     * Source Reference: https://www.w3schools.com/cssref/css3_pr_columns.asp
     * Source Reference: https://developer.mozilla.org/en-US/docs/Web/CSS/columns
     *
     * example:
     * label {
     * 		columns: auto 50;
     * }
     *
     *
     */
    ImmutableSet<String> columns_Literals = ImmutableSet.of( "auto", "initial", "inherit" );

    Property columns_Property =
            new Property( BIT_STRING | BIT_QUANTITY,   // strings and numbers allowed
                    columns_Literals,
                    zeroFns);
    builder.put("columns", columns_Property);




    /*
     * Property Name: float-offset
     * Property Syntax: float-offset: {length} {length}
     *
     * Source Reference: http://www.cssportal.com/css-properties/float-offset.php
     *
     * example:
     * label {
     * 		float-offset: 20% 50px;
     * }
     *
     *
     */
    ImmutableSet<String> float_offset_Literals = ImmutableSet.of( "" );

    Property float_offset_Property =
            new Property( BIT_QUANTITY,   // only numbers allowed
                    float_offset_Literals,
                    zeroFns);
    builder.put("float-offset", float_offset_Property);




    /*
     * Property Name: font-size-adjust
     * Property Syntax: font-size-adjust: {number}|none|initial|inherit;
     *
     * Source Reference: https://www.w3schools.com/cssref/css3_pr_font-size-adjust.asp
     *
     * example:
     * label {
     * 		font-size-adjust: 50px;
     * }
     *
     *
     */
    ImmutableSet<String> font_size_adjust_Literals = ImmutableSet.of( "none", "initial", "inherit" );

    Property font_size_adjust_Property =
            new Property( BIT_STRING | BIT_QUANTITY,   // strings and numbers allowed
                    font_size_adjust_Literals,
                    zeroFns);
    builder.put("font-size-adjust", font_size_adjust_Property);




    /*
     * Property Name: grid-column
     * Property Syntax: grid-column: {length}|%|none|inherit;
     *
     * Source Reference: https://www.w3schools.com/cssref/css3_pr_grid-column.asp
     *
     * example:
     * label {
     * 		grid-column: 25%;
     * }
     *
     *
     */
    ImmutableSet<String> grid_columns_Literals = ImmutableSet.of( "none", "inherit" );

    Property grid_columns_Property =
            new Property( BIT_STRING | BIT_QUANTITY,   // strings and numbers allowed
                    grid_columns_Literals,
                    zeroFns);
    builder.put("grid-column", grid_columns_Property);





    /*
     * Property Name: grid-row
     * Property Syntax: grid-row: {length}|%|none|inherit;
     *
     * Source Reference: https://www.w3schools.com/cssref/css3_pr_grid-row.asp
     *
     * example:
     * label {
     * 		grid-row: 25%;
     * }
     *
     *
     */
    builder.put("grid-row", grid_columns_Property);    // same as 'grid-column'





    /*
     * Property Name: hanging-punctuation
     * Property Syntax: hanging-punctuation: none|first|last|allow-end|force-end|initial|inherit;
     *
     * Source Reference: https://www.w3schools.com/cssref/css3_pr_hanging-punctuation.asp
     *
     * example:
     * label {
     * 		 hanging-punctuation: first;
     * }
     *
     *
     */
    ImmutableSet<String> hanging_punctuation_Literals = ImmutableSet.of( "none", "first", "last", "allow-end", "force-end", "initial", "inherit" );

    Property hanging_punctuation_Property =
            new Property( BIT_STRING,   // strings allowed
                    hanging_punctuation_Literals,
                    zeroFns);
    builder.put("hanging-punctuation", hanging_punctuation_Property);





    /*
     * Property Name: line-break
     * Property Syntax: line-break: auto|loose|normal|strict;
     *
     * Source Reference: https://developer.mozilla.org/en-US/docs/Web/CSS/line-break
     *
     * example:
     * label {
     * 		 line-break: normal;
     * }
     *
     *
     */
    ImmutableSet<String> line_break_Literals = ImmutableSet.of( "auto", "loose", "normal", "strict" );

    Property line_break_Property =
            new Property( BIT_STRING,   // strings allowed
                    line_break_Literals,
                    zeroFns);
    builder.put("line-break", line_break_Property);




    /*
     * Property Name: overflow-style
     * Property Syntax: overflow-style: auto|scrollbar|panner|move|marquee;
     *
     * Source Reference: https://www.w3schools.com/CSSref/css3_pr_overflow-style.asp
     *
     * example:
     * label {
     * 		 overflow-style: panner;
     * }
     *
     *
     */
    ImmutableSet<String> overflow_style_Literals = ImmutableSet.of( "auto", "scrollbar", "panner", "move", "marquee" );

    Property overflow_style_Property =
            new Property( BIT_STRING,   // strings allowed
                    overflow_style_Literals,
                    zeroFns);
    builder.put("overflow-style", overflow_style_Property);





    /*
     * Property Name: overflow-wrap
     * Property Syntax: overflow-wrap: normal|break-word|inherit|initial|unset;
     *
     * Source Reference: https://developer.mozilla.org/en-US/docs/Web/CSS/overflow-wrap?v=control
     *
     * example:
     * label {
     * 		 overflow-wrap: break-word;
     * }
     *
     *
     */
    ImmutableSet<String> overflow_wrap_Literals = ImmutableSet.of( "normal", "break-word", "inherit", "initial", "unset" );

    Property overflow_wrap_Property =
            new Property( BIT_STRING,   // strings allowed
                    overflow_wrap_Literals,
                    zeroFns);
    builder.put("overflow-wrap", overflow_wrap_Property);




    /*
     * Property Name: punctuation-trim
     * Property Syntax: punctuation-trim: none|start|end|allow-end|adjacent;
     *
     * Source Reference: https://www.w3schools.com/cssref/css3_pr_punctuation-trim.asp
     *
     * example:
     * label {
     * 		 punctuation-trim: allow-end;
     * }
     *
     *
     */
    ImmutableSet<String> punctuation_trim_Literals = ImmutableSet.of( "none", "start", "end", "allow-end", "adjacent" );

    Property punctuation_trim_Property =
            new Property( BIT_STRING,   // strings allowed
                    punctuation_trim_Literals,
                    zeroFns);
    builder.put("punctuation-trim", punctuation_trim_Property);




    /*
     * Property Name: text-decoration-color
     * Property Syntax: text-decoration-color: {color}|initial|inherit;
     *
     * Source Reference: https://www.w3schools.com/cssref/css3_pr_text-decoration-color.asp
     *
     * example:
     * label {
     * 		 text-decoration-color: red;
     * }
     *
     *
     */

    Property text_decoration_color_Property =
            new Property(
                    258, union(mozOpacityLiterals0, mozOutlineLiterals0),
                    mozOutlineFunctions);
    builder.put("text-decoration-color", text_decoration_color_Property);



    /*
     * Property Name: text-decoration-line
     * Property Syntax: text-decoration-line: none|underline|overline|line-through|initial|inherit;
     *
     * Source Reference: https://www.w3schools.com/cssref/css3_pr_text-decoration-line.asp
     *
     * example:
     * label {
     * 		 text-decoration-line: none;
     * }
     *
     *
     */
    ImmutableSet<String> text_decoration_line_Literals = ImmutableSet.of( "none", "underline", "overline", "line-through", "initial", "inherit" );

    Property text_decoration_line_Property =
            new Property( BIT_STRING,   // strings allowed
                    text_decoration_line_Literals,
                    zeroFns);
    builder.put("text-decoration-line", text_decoration_line_Property);





    /*
     * Property Name: text-decoration-skip
     * Property Syntax: text-decoration-skip: none|objects|spaces|ink|edges|box-decoration|unset|initial|inherit;
     *
     * Source Reference: https://developer.mozilla.org/en-US/docs/Web/CSS/text-decoration-skip
     *
     * example:
     * label {
     * 		 text-decoration-skip: ink;
     * }
     *
     *
     */
    ImmutableSet<String> text_decoration_skip_Literals = ImmutableSet.of( "none", "objects", "spaces", "ink", "edges", "box-decoration", "inherit", "initial", "unset" );

    Property text_decoration_skip_Property =
            new Property( BIT_STRING,   // strings allowed
                    text_decoration_skip_Literals,
                    zeroFns);
    builder.put("text-decoration-skip", text_decoration_skip_Property);




    /*
     * Property Name: text-decoration-style
     * Property Syntax: text-decoration-style: solid|double|dotted|dashed|wavy|initial|inherit;
     *
     * Source Reference: https://www.w3schools.com/cssref/css3_pr_text-decoration-style.asp
     *
     * example:
     * label {
     * 		 text-decoration-style: dashed;
     * }
     *
     *
     */
    ImmutableSet<String> text_decoration_style_Literals = ImmutableSet.of( "solid", "double", "dotted", "dashed", "wavy", "inherit", "initial" );

    Property text_decoration_style_Property =
            new Property( BIT_STRING,   // strings allowed
                    text_decoration_style_Literals,
                    zeroFns);
    builder.put("text-decoration-style", text_decoration_style_Property);




    /*
     * Property Name: text-justify
     * Property Syntax: text-justify: auto|inter-word|inter-ideograph|inter-cluster|distribute|kashida|trim|initial|inherit;
     *
     * Source Reference: https://www.w3schools.com/cssref/css3_pr_text-justify.asp
     *
     * example:
     * label {
     * 		 text-justify: inter-word;
     * }
     *
     *
     */
    ImmutableSet<String> text_justify_Literals = ImmutableSet.of( "auto", "inter-word", "inter-ideograph", "inter-cluster", "distribute", "kashida", "trim", "inherit", "initial" );

    Property text_justify_Property =
            new Property( BIT_STRING,   // strings allowed
                    text_justify_Literals,
                    zeroFns);
    builder.put("text-justify", text_justify_Property);





    /*
     * Property Name: text-outline
     * Property Syntax: text-outline: {thickness} {blur} {color};
     *
     * Source Reference: https://www.w3schools.com/cssref/css3_pr_text-outline.asp
     *
     * example:
     * label {
     * 		 text-outline: 2px 2px #ff0000;
     * }
     *
     *
     */
    Property text_outline_Property =
            new Property(
                    258 | BIT_QUANTITY,   // colors and numbers allowed
                    union(mozOpacityLiterals0, mozOutlineLiterals0),
                    mozOutlineFunctions);
    builder.put("text-outline", text_outline_Property);





    /*
     * Property Name: text-space-collapse
     * Property Syntax: text-space-collapse: collapse|preserve|preserve-breaks;
     *
     * Source Reference: https://www.htmlvalidator.com/help.php?m=1&h=text-space-collapse
     *
     * example:
     * label {
     * 		 text-space-collapse: preserve;
     * }
     *
     *
     */
    ImmutableSet<String> text_space_collapse_Literals = ImmutableSet.of( "collapse", "preserve", "preserve-breaks" );

    Property text_space_collapse_Property =
            new Property( BIT_STRING,   // strings allowed
                    text_space_collapse_Literals,
                    zeroFns);
    builder.put("text-space-collapse", text_space_collapse_Property);





    /*
     * Property Name: text-underline-position
     * Property Syntax: text-underline-position: auto|under|left|right|under left|right under|inherit|initial|unset;
     *
     *
     * Source Reference: https://developer.mozilla.org/en-US/docs/Web/CSS/text-underline-position
     *
     * example:
     * label {
     * 		 text-underline-position: right under;
     * }
     *
     *
     */
    ImmutableSet<String> text_underline_position_Literals = ImmutableSet.of( "auto", "under", "left", "right", "under", "inherit", "initial", "unset" );

    Property text_underline_position_Property =
            new Property( BIT_STRING,   // strings allowed
                    text_underline_position_Literals,
                    zeroFns);
    builder.put("text-underline-position", text_underline_position_Property);




    /*
     * Property Name: word-break
     * Property Syntax: word-break: normal|break-all|keep-all|initial|inherit;
     *
     *
     * Source Reference: https://www.w3schools.com/cssref/css3_pr_word-break.asp
     *
     * example:
     * label {
     * 		 word-break: keep-all;
     * }
     *
     *
     */
    ImmutableSet<String> word_break_Literals = ImmutableSet.of( "normal", "break-all", "keep-all", "inherit", "initial" );

    Property word_break_Property =
            new Property( BIT_STRING,   // strings allowed
                    word_break_Literals,
                    zeroFns);
    builder.put("word-break", word_break_Property);




    /*********************************************************************************************************/
    /**                                                                                                     **/
    /**                                                                                                     **/
    /**                                      Touchnet Entries                                               **/
    /**                                                                                                     **/
    /**                                            END                                                      **/
    /**                                                                                                     **/
    /**                                                                                                     **/
    /*********************************************************************************************************/
    Property mozBorderRadius =
            new Property(5, mozBorderRadiusLiterals0, zeroFns);
    builder.put("-moz-border-radius", mozBorderRadius);
    Property mozBorderRadiusBottomleft =
            new Property(5, ImmutableSet.<String>of(), zeroFns);
    builder.put("-moz-border-radius-bottomleft", mozBorderRadiusBottomleft);
    Property mozOpacity = new Property(1, mozOpacityLiterals0, zeroFns);
    builder.put("-moz-opacity", mozOpacity);
    @SuppressWarnings("unchecked")
    Property mozOutline = new Property(
            7,
            union(mozOutlineLiterals0, mozOutlineLiterals1, mozOutlineLiterals2,
                    mozOutlineLiterals3),
            mozOutlineFunctions);
    builder.put("-moz-outline", mozOutline);
    @SuppressWarnings("unchecked")
    Property mozOutlineColor = new Property(
            2, union(mozOutlineColorLiterals0, mozOutlineLiterals0),
            mozOutlineFunctions);
    builder.put("-moz-outline-color", mozOutlineColor);
    @SuppressWarnings("unchecked")
    Property mozOutlineStyle = new Property(
            0, union(mozOutlineLiterals1, mozOutlineStyleLiterals0), zeroFns);
    builder.put("-moz-outline-style", mozOutlineStyle);
    @SuppressWarnings("unchecked")
    Property mozOutlineWidth = new Property(
            5, union(mozOutlineLiterals2, mozOutlineWidthLiterals0), zeroFns);
    builder.put("-moz-outline-width", mozOutlineWidth);
    Property oTextOverflow = new Property(0, oTextOverflowLiterals0, zeroFns);
    builder.put("-o-text-overflow", oTextOverflow);
    @SuppressWarnings("unchecked")
    Property azimuth = new Property(
            5, union(azimuthLiterals0, azimuthLiterals1, azimuthLiterals2),
            zeroFns);
    builder.put("azimuth", azimuth);
    @SuppressWarnings("unchecked")
    Property background = new Property(
            23,
            union(azimuthLiterals1, backgroundLiterals0, backgroundLiterals1,
                    backgroundLiterals2, backgroundLiterals3, mozOutlineLiterals0),
            backgroundFunctions);
    builder.put("background", background);
    builder.put("background-attachment",
            new Property(0, backgroundAttachmentLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    Property backgroundColor = new Property(
            258, union(backgroundColorLiterals0, mozOutlineLiterals0),
            mozOutlineFunctions);
    builder.put("background-color", backgroundColor);
    builder.put("background-image",
            new Property(16, backgroundImageLiterals0,
                    backgroundImageFunctions));
    @SuppressWarnings("unchecked")
    Property backgroundPosition = new Property(
            5,
            union(azimuthLiterals1, backgroundLiterals2,
                    backgroundPositionLiterals0),
            zeroFns);
    builder.put("background-position", backgroundPosition);
    @SuppressWarnings("unchecked")
    Property backgroundRepeat = new Property(
            0, union(backgroundLiterals1, backgroundRepeatLiterals0), zeroFns);
    builder.put("background-repeat", backgroundRepeat);
    Property backgroundSize = new Property(
            5, backgroundSizeLiterals, zeroFns);
    builder.put("background-size", backgroundSize);
    @SuppressWarnings("unchecked")
    Property border = new Property(
            7,
            union(borderLiterals0, mozOutlineLiterals0, mozOutlineLiterals1,
                    mozOutlineLiterals2),
            mozOutlineFunctions);
    builder.put("border", border);
    @SuppressWarnings("unchecked")
    Property borderBottomColor = new Property(
            2, union(backgroundColorLiterals0, mozOutlineLiterals0),
            mozOutlineFunctions);
    builder.put("border-bottom-color", borderBottomColor);
    builder.put("border-collapse",
            new Property(0, borderCollapseLiterals0, zeroFns));
    builder.put("border-image-source", new Property(
            16, cueLiterals0, backgroundImageFunctions));
    Property borderSpacing = new Property(5, mozOpacityLiterals0, zeroFns);
    builder.put("border-spacing", borderSpacing);
    Property bottom = new Property(5, bottomLiterals0, zeroFns);
    builder.put("bottom", bottom);
    @SuppressWarnings("unchecked")
    Property boxShadow = new Property(
            7, union(boxShadowLiterals0, mozOutlineLiterals0), mozOutlineFunctions);
    builder.put("box-shadow", boxShadow);
    @SuppressWarnings("unchecked")
    Property captionSide = new Property(
            0, union(backgroundLiterals2, mozOpacityLiterals0), zeroFns);
    builder.put("caption-side", captionSide);
    @SuppressWarnings("unchecked")
    Property clear = new Property(
            0, union(azimuthLiterals1, clearLiterals0), zeroFns);
    builder.put("clear", clear);
    builder.put("clip", new Property(0, bottomLiterals0, clipFunctions));
    @SuppressWarnings("unchecked")
    Property color = new Property(
            258, union(mozOpacityLiterals0, mozOutlineLiterals0),
            mozOutlineFunctions);
    builder.put("color", color);
    builder.put("content", new Property(8, contentLiterals0, zeroFns));
    Property cue = new Property(16, cueLiterals0, zeroFns);
    builder.put("cue", cue);
    @SuppressWarnings("unchecked")
    Property cursor = new Property(
            272, union(cursorLiterals0, cursorLiterals1), zeroFns);
    builder.put("cursor", cursor);
    @SuppressWarnings("unchecked")
    Property direction = new Property(
            0, union(directionLiterals0, mozOpacityLiterals0), zeroFns);
    builder.put("direction", direction);
    @SuppressWarnings("unchecked")
    Property display = new Property(
            0, union(cueLiterals0, displayLiterals0), zeroFns);
    builder.put("display", display);
    @SuppressWarnings("unchecked")
    Property elevation = new Property(
            5, union(elevationLiterals0, mozOpacityLiterals0), zeroFns);
    builder.put("elevation", elevation);
    @SuppressWarnings("unchecked")
    Property emptyCells = new Property(
            0, union(emptyCellsLiterals0, mozOpacityLiterals0), zeroFns);
    builder.put("empty-cells", emptyCells);
    //builder.put("filter",
    //            new Property(0, ImmutableSet.<String>of(), filterFunctions));
    @SuppressWarnings("unchecked")
    Property cssFloat = new Property(
            0, union(azimuthLiterals1, cueLiterals0), zeroFns);
    builder.put("float", cssFloat);
    @SuppressWarnings("unchecked")
    Property font = new Property(
            73,
            union(fontLiterals0, fontLiterals1, fontLiterals2, fontLiterals3,
                    fontLiterals4, fontLiterals5),
            zeroFns);
    builder.put("font", font);
    @SuppressWarnings("unchecked")
    Property fontFamily = new Property(
            72, union(fontFamilyLiterals0, fontLiterals3), zeroFns);    // TODO TN modified was 72, TN set to 10
    builder.put("font-family", fontFamily);
    @SuppressWarnings("unchecked")
    Property fontSize = new Property(
            1, union(fontLiterals1, mozOutlineWidthLiterals0), zeroFns);
    builder.put("font-size", fontSize);
    @SuppressWarnings("unchecked")
    Property fontStretch = new Property(
            0, union(fontStretchLiterals0, fontStretchLiterals1), zeroFns);
    builder.put("font-stretch", fontStretch);
    @SuppressWarnings("unchecked")
    Property fontStyle = new Property(
            0, union(fontLiterals4, fontStyleLiterals0), zeroFns);
    builder.put("font-style", fontStyle);
    builder.put("font-variant", new Property(
            0, fontVariantLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    Property fontWeight = new Property(
            0, union(fontLiterals0, fontStyleLiterals0), zeroFns);
    builder.put("font-weight", fontWeight);
    Property height = new Property(5, bottomLiterals0, zeroFns);
    builder.put("height", height);
    Property letterSpacing = new Property(5, fontStyleLiterals0, zeroFns);
    builder.put("letter-spacing", letterSpacing);
    builder.put("line-height", new Property(1, fontStyleLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    Property listStyle = new Property(
            16,
            union(listStyleLiterals0, listStyleLiterals1, listStyleLiterals2),
            backgroundImageFunctions);
    builder.put("list-style", listStyle);
    builder.put("list-style-image", new Property(
            16, cueLiterals0, backgroundImageFunctions));
    @SuppressWarnings("unchecked")
    Property listStylePosition = new Property(
            0, union(listStyleLiterals1, mozOpacityLiterals0), zeroFns);
    builder.put("list-style-position", listStylePosition);
    @SuppressWarnings("unchecked")
    Property listStyleType = new Property(
            0, union(listStyleLiterals0, listStyleLiterals2), zeroFns);
    builder.put("list-style-type", listStyleType);
    Property margin = new Property(5, bottomLiterals0, zeroFns);    // was 1  TN modified   TODO
    builder.put("margin", margin);
    Property maxHeight = new Property(1, maxHeightLiterals0, zeroFns);
    builder.put("max-height", maxHeight);
    Property opacity = new Property(1, mozOpacityLiterals0, zeroFns);
    builder.put("opacity", opacity);
    builder.put("overflow", new Property(0, overflowLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    Property overflowX = new Property(
            0, union(overflowXLiterals0, overflowXLiterals1), zeroFns);
    builder.put("overflow-x", overflowX);
    Property padding = new Property(5, mozOpacityLiterals0, zeroFns);       // was 1  TN modified   TODO
    builder.put("padding", padding);
    @SuppressWarnings("unchecked")
    Property pageBreakAfter = new Property(
            0, union(azimuthLiterals1, pageBreakAfterLiterals0), zeroFns);
    builder.put("page-break-after", pageBreakAfter);
    builder.put("page-break-inside", new Property(
            0, pageBreakInsideLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    Property pitch = new Property(
            5, union(mozOutlineWidthLiterals0, pitchLiterals0), zeroFns);
    builder.put("pitch", pitch);
    builder.put("play-during", new Property(
            16, playDuringLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    Property position = new Property(
            0, union(mozOpacityLiterals0, positionLiterals0), zeroFns);
    builder.put("position", position);
    builder.put("quotes", new Property(8, cueLiterals0, zeroFns));
    builder.put("speak", new Property(0, speakLiterals0, zeroFns));
    builder.put("speak-header", new Property(
            0, speakHeaderLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    Property speakNumeral = new Property(
            0, union(mozOpacityLiterals0, speakNumeralLiterals0), zeroFns);
    builder.put("speak-numeral", speakNumeral);
    builder.put("speak-punctuation", new Property(
            0, speakPunctuationLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    Property speechRate = new Property(
            5, union(mozOutlineWidthLiterals0, speechRateLiterals0), zeroFns);
    builder.put("speech-rate", speechRate);
    builder.put("table-layout", new Property(
            0, tableLayoutLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    Property textAlign = new Property(
            0, union(azimuthLiterals1, textAlignLiterals0), zeroFns);
    builder.put("text-align", textAlign);
    @SuppressWarnings("unchecked")
    Property textDecoration = new Property(
            0, union(cueLiterals0, textDecorationLiterals0), zeroFns);
    builder.put("text-decoration", textDecoration);
    @SuppressWarnings("unchecked")
    Property textTransform = new Property(
            0, union(cueLiterals0, textTransformLiterals0), zeroFns);
    builder.put("text-transform", textTransform);
    @SuppressWarnings("unchecked")
    Property textWrap = new Property(
            0, union(contentLiterals0, textWrapLiterals0), zeroFns);
    builder.put("text-wrap", textWrap);
    @SuppressWarnings("unchecked")
    Property unicodeBidi = new Property(
            0, union(fontStyleLiterals0, unicodeBidiLiterals0), zeroFns);
    builder.put("unicode-bidi", unicodeBidi);
    @SuppressWarnings("unchecked")
    Property verticalAlign = new Property(
            5,
            union(backgroundLiterals2, mozOpacityLiterals0, verticalAlignLiterals0),
            zeroFns);
    builder.put("vertical-align", verticalAlign);
    builder.put("visibility", new Property(0, visibilityLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    Property voiceFamily = new Property(
            8, union(fontFamilyLiterals0, voiceFamilyLiterals0), zeroFns);
    builder.put("voice-family", voiceFamily);
    @SuppressWarnings("unchecked")
    Property volume = new Property(
            1, union(mozOutlineWidthLiterals0, volumeLiterals0), zeroFns);
    builder.put("volume", volume);
    @SuppressWarnings("unchecked")
    Property whiteSpace = new Property(
            0, union(fontStyleLiterals0, whiteSpaceLiterals0), zeroFns);
    builder.put("white-space", whiteSpace);
    builder.put("word-wrap", new Property(0, wordWrapLiterals0, zeroFns));
    builder.put("zoom", new Property(1, fontStretchLiterals1, zeroFns));
    Property rgb$Fun = new Property(1, rgb$FunLiterals0, zeroFns);
    builder.put("rgb()", rgb$Fun);
    builder.put("rgba()", rgb$Fun);
    builder.put("hsl()", rgb$Fun);
    builder.put("hsla()", rgb$Fun);
    @SuppressWarnings("unchecked")
    Property image$Fun = new Property(
            18, union(mozOutlineLiterals0, rgb$FunLiterals0), mozOutlineFunctions);
    builder.put("image()", image$Fun);
    @SuppressWarnings("unchecked")
    Property linearGradient$Fun = new Property(
            7,
            union(azimuthLiterals1, backgroundLiterals2,
                    linearGradient$FunLiterals0, mozOutlineLiterals0),
            mozOutlineFunctions);
    builder.put("linear-gradient()", linearGradient$Fun);
    builder.put("-moz-linear-gradient()", linearGradient$Fun);       // TODO TN modified
    builder.put("-webkit-linear-gradient()", linearGradient$Fun);    // TODO TN modified
    @SuppressWarnings("unchecked")
    Property radialGradient$Fun = new Property(
            7,
            union(azimuthLiterals1, backgroundLiterals2, mozOutlineLiterals0,
                    radialGradient$FunLiterals0, radialGradient$FunLiterals1),
            mozOutlineFunctions);
    builder.put("radial-gradient()", radialGradient$Fun);
    builder.put("rect()", new Property(5, rect$FunLiterals0, zeroFns));
    //builder.put("alpha()", new Property(1, alpha$FunLiterals0, zeroFns));
    builder.put("-moz-border-radius-bottomright", mozBorderRadiusBottomleft);
    builder.put("-moz-border-radius-topleft", mozBorderRadiusBottomleft);
    builder.put("-moz-border-radius-topright", mozBorderRadiusBottomleft);
    builder.put("-moz-box-shadow", boxShadow);
    builder.put("-webkit-border-bottom-left-radius", mozBorderRadiusBottomleft);
    builder.put("-webkit-border-bottom-right-radius",
            mozBorderRadiusBottomleft);
    builder.put("-webkit-border-radius", mozBorderRadius);
    builder.put("-webkit-border-radius-bottom-left", mozBorderRadiusBottomleft);
    builder.put("-webkit-border-radius-bottom-right",
            mozBorderRadiusBottomleft);
    builder.put("-webkit-border-radius-top-left", mozBorderRadiusBottomleft);
    builder.put("-webkit-border-radius-top-right", mozBorderRadiusBottomleft);
    builder.put("-webkit-border-top-left-radius", mozBorderRadiusBottomleft);
    builder.put("-webkit-border-top-right-radius", mozBorderRadiusBottomleft);
    builder.put("-webkit-box-shadow", boxShadow);
    builder.put("border-bottom", border);
    builder.put("border-bottom-left-radius", mozBorderRadiusBottomleft);
    builder.put("border-bottom-right-radius", mozBorderRadiusBottomleft);
    builder.put("border-bottom-style", mozOutlineStyle);
    builder.put("border-bottom-width", mozOutlineWidth);
    builder.put("border-color", borderBottomColor);
    builder.put("border-left", border);
    builder.put("border-left-color", borderBottomColor);
    builder.put("border-left-style", mozOutlineStyle);
    builder.put("border-left-width", mozOutlineWidth);
    builder.put("border-radius", mozBorderRadius);
    builder.put("border-right", border);
    builder.put("border-right-color", borderBottomColor);
    builder.put("border-right-style", mozOutlineStyle);
    builder.put("border-right-width", mozOutlineWidth);
    builder.put("border-style", mozOutlineStyle);
    builder.put("border-top", border);
    builder.put("border-top-color", borderBottomColor);
    builder.put("border-top-left-radius", mozBorderRadiusBottomleft);
    builder.put("border-top-right-radius", mozBorderRadiusBottomleft);
    builder.put("border-top-style", mozOutlineStyle);
    builder.put("border-top-width", mozOutlineWidth);
    builder.put("border-width", mozOutlineWidth);
    builder.put("cue-after", cue);
    builder.put("cue-before", cue);
    builder.put("left", height);
    builder.put("margin-bottom", margin);
    builder.put("margin-left", margin);
    builder.put("margin-right", margin);
    builder.put("margin-top", margin);
    builder.put("max-width", maxHeight);
    builder.put("min-height", margin);
    builder.put("min-width", margin);
    builder.put("outline", mozOutline);
    builder.put("outline-color", mozOutlineColor);
    builder.put("outline-style", mozOutlineStyle);
    builder.put("outline-width", mozOutlineWidth);
    builder.put("overflow-y", overflowX);
    builder.put("padding-bottom", padding);
    builder.put("padding-left", padding);
    builder.put("padding-right", padding);
    builder.put("padding-top", padding);
    builder.put("page-break-before", pageBreakAfter);
    builder.put("pause", borderSpacing);
    builder.put("pause-after", borderSpacing);
    builder.put("pause-before", borderSpacing);
    builder.put("pitch-range", borderSpacing);
    builder.put("richness", borderSpacing);
    builder.put("right", height);
    builder.put("stress", borderSpacing);
    builder.put("text-indent", borderSpacing);
    builder.put("text-overflow", oTextOverflow);
    builder.put("text-shadow", boxShadow);
    builder.put("top", height);
    builder.put("width", margin);
    builder.put("word-spacing", letterSpacing);
    builder.put("z-index", bottom);
    builder.put("repeating-linear-gradient()", linearGradient$Fun);
    builder.put("repeating-radial-gradient()", radialGradient$Fun);
    DEFINITIONS = builder.build();
  }

  private static <T> ImmutableSet<T> union(
          @SuppressWarnings("unchecked") ImmutableSet<T>... subsets) {
    ImmutableSet.Builder<T> all = ImmutableSet.builder();
    for (ImmutableSet<T> subset : subsets) {
      all.addAll(subset);
    }
    return all.build();
  }

  static final ImmutableSet<String> DEFAULT_WHITELIST = ImmutableSet.of(
          "-moz-border-radius",
          "-moz-border-radius-bottomleft",
          "-moz-border-radius-bottomright",
          "-moz-border-radius-topleft",
          "-moz-border-radius-topright",
          "-moz-box-shadow",
          "-moz-outline",
          "-moz-outline-color",
          "-moz-outline-style",
          "-moz-outline-width",
          "-o-text-overflow",
          "-webkit-border-bottom-left-radius",
          "-webkit-border-bottom-right-radius",
          "-webkit-border-radius",
          "-webkit-border-radius-bottom-left",
          "-webkit-border-radius-bottom-right",
          "-webkit-border-radius-top-left",
          "-webkit-border-radius-top-right",
          "-webkit-border-top-left-radius",
          "-webkit-border-top-right-radius",
          "-webkit-box-shadow",
          "azimuth",
          "background",
          "background-attachment",
          "background-color",
          "background-image",
          "background-position",
          "background-repeat",
          "background-size",
          "border",
          "border-bottom",
          "border-bottom-color",
          "border-bottom-left-radius",
          "border-bottom-right-radius",
          "border-bottom-style",
          "border-bottom-width",
          "border-collapse",
          "border-color",
          "border-image-source",
          "border-left",
          "border-left-color",
          "border-left-style",
          "border-left-width",
          "border-radius",
          "border-right",
          "border-right-color",
          "border-right-style",
          "border-right-width",
          "border-spacing",
          "border-style",
          "border-top",
          "border-top-color",
          "border-top-left-radius",
          "border-top-right-radius",
          "border-top-style",
          "border-top-width",
          "border-width",
          "box-shadow",
          "caption-side",
          "color",
          "cue",
          "cue-after",
          "cue-before",
          "direction",
          "elevation",
          "empty-cells",
          "font",
          "font-family",
          "font-size",
          "font-stretch",
          "font-style",
          "font-variant",
          "font-weight",
          "height",
          "image()",
          "letter-spacing",
          "line-height",
          "linear-gradient()",
          "-moz-linear-gradient()",            // TODO TN modified
          "-webkit-linear-gradient()",         // TODO TN modified
          "list-style",
          "list-style-image",
          "list-style-position",
          "list-style-type",
          "margin",
          "margin-bottom",
          "margin-left",
          "margin-right",
          "margin-top",
          "max-height",
          "max-width",
          "min-height",
          "min-width",
          "outline",
          "outline-color",
          "outline-style",
          "outline-width",
          "padding",
          "padding-bottom",
          "padding-left",
          "padding-right",
          "padding-top",
          "pause",
          "pause-after",
          "pause-before",
          "pitch",
          "pitch-range",
          "quotes",
          "radial-gradient()",
          "rect()",
          "repeating-linear-gradient()",
          "repeating-radial-gradient()",
          "rgb()",
          "rgba()",
          "hsl()",
          "hsla()",
          "richness",
          "speak",
          "speak-header",
          "speak-numeral",
          "speak-punctuation",
          "speech-rate",
          "stress",
          "table-layout",
          "text-align",
          "text-decoration",
          "text-indent",
          "text-overflow",
          "text-shadow",
          "text-transform",
          "text-wrap",
          "unicode-bidi",
          "vertical-align",
          "voice-family",
          "volume",
          "white-space",
          "width",
          "word-spacing",
          "word-wrap"
  );

  /**
   * A schema that includes only those properties on the default schema
   * white-list.
   */
  public static final CssSchema DEFAULT =
          CssSchema.withProperties(DEFAULT_WHITELIST);

  /** Dumps key and literal list to stdout for easy examination. */
  public static void main(String... argv) {
    SortedSet<String> keys = Sets.newTreeSet();
    SortedSet<String> literals = Sets.newTreeSet();

    for (ImmutableMap.Entry<String, Property> e : DEFINITIONS.entrySet()) {
      keys.add(e.getKey());
      literals.addAll(e.getValue().literals);
    }

    System.out.println(
            "# Below two blocks of tokens.\n"
                    + "#\n"
                    + "# First are all property names.\n"
                    + "# Those followed by an asterisk (*) are in the default white-list.\n"
                    + "#\n"
                    + "# Second are the literal tokens recognized in any defined property\n"
                    + "# value.\n"
    );
    for (String key : keys) {
      System.out.print(key);
      if (DEFAULT_WHITELIST.contains(key)) { System.out.print("*"); }
      System.out.println();
    }
    System.out.println();
    for (String literal : literals) {
      System.out.println(literal);
    }
  }
}
