package androidx.constraintlayout.core.parser;

import androidx.constraintlayout.widget.ConstraintLayout;
/* loaded from: classes.dex */
public class CLParser {
    static boolean DEBUG = false;
    private boolean hasComment = false;
    private int lineNumber;
    private String mContent;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public enum TYPE {
        UNKNOWN,
        OBJECT,
        ARRAY,
        NUMBER,
        STRING,
        KEY,
        TOKEN
    }

    public static CLObject parse(String string) throws CLParsingException {
        return new CLParser(string).parse();
    }

    public CLParser(String content) {
        this.mContent = content;
    }

    /* JADX WARN: Code restructure failed: missing block: B:82:0x0142, code lost:
        if (r6 != ':') goto L31;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public androidx.constraintlayout.core.parser.CLObject parse() throws androidx.constraintlayout.core.parser.CLParsingException {
        /*
            Method dump skipped, instructions count: 474
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.parser.CLParser.parse():androidx.constraintlayout.core.parser.CLObject");
    }

    private CLElement getNextJsonElement(int position, char c, CLElement currentElement, char[] content) throws CLParsingException {
        switch (c) {
            case '\t':
            case '\n':
            case '\r':
            case ' ':
            case ',':
            case ':':
                return currentElement;
            case '\"':
            case '\'':
                if (currentElement instanceof CLObject) {
                    return createElement(currentElement, position, TYPE.KEY, true, content);
                }
                return createElement(currentElement, position, TYPE.STRING, true, content);
            case '+':
            case '-':
            case '.':
            case ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE /* 48 */:
            case ConstraintLayout.LayoutParams.Table.LAYOUT_EDITOR_ABSOLUTEX /* 49 */:
            case '2':
            case ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_TAG /* 51 */:
            case ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_BASELINE_TO_TOP_OF /* 52 */:
            case ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_BASELINE_TO_BOTTOM_OF /* 53 */:
            case ConstraintLayout.LayoutParams.Table.LAYOUT_MARGIN_BASELINE /* 54 */:
            case ConstraintLayout.LayoutParams.Table.LAYOUT_GONE_MARGIN_BASELINE /* 55 */:
            case '8':
            case '9':
                return createElement(currentElement, position, TYPE.NUMBER, true, content);
            case '/':
                if (position + 1 < content.length && content[position + 1] == '/') {
                    this.hasComment = true;
                    return currentElement;
                }
                return currentElement;
            case '[':
                return createElement(currentElement, position, TYPE.ARRAY, true, content);
            case ']':
            case '}':
                currentElement.setEnd(position - 1);
                CLElement currentElement2 = currentElement.getContainer();
                currentElement2.setEnd(position);
                return currentElement2;
            case '{':
                return createElement(currentElement, position, TYPE.OBJECT, true, content);
            default:
                if ((currentElement instanceof CLContainer) && !(currentElement instanceof CLObject)) {
                    CLElement currentElement3 = createElement(currentElement, position, TYPE.TOKEN, true, content);
                    CLToken token = (CLToken) currentElement3;
                    if (!token.validate(c, position)) {
                        throw new CLParsingException("incorrect token <" + c + "> at line " + this.lineNumber, token);
                    }
                    return currentElement3;
                }
                return createElement(currentElement, position, TYPE.KEY, true, content);
        }
    }

    private CLElement createElement(CLElement currentElement, int position, TYPE type, boolean applyStart, char[] content) {
        CLElement newElement = null;
        if (DEBUG) {
            System.out.println("CREATE " + type + " at " + content[position]);
        }
        switch (type) {
            case OBJECT:
                newElement = CLObject.allocate(content);
                position++;
                break;
            case ARRAY:
                newElement = CLArray.allocate(content);
                position++;
                break;
            case STRING:
                newElement = CLString.allocate(content);
                break;
            case NUMBER:
                newElement = CLNumber.allocate(content);
                break;
            case KEY:
                newElement = CLKey.allocate(content);
                break;
            case TOKEN:
                newElement = CLToken.allocate(content);
                break;
        }
        if (newElement == null) {
            return null;
        }
        newElement.setLine(this.lineNumber);
        if (applyStart) {
            newElement.setStart(position);
        }
        if (currentElement instanceof CLContainer) {
            CLContainer container = (CLContainer) currentElement;
            newElement.setContainer(container);
        }
        return newElement;
    }
}
