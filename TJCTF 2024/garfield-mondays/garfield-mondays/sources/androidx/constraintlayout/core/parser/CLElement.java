package androidx.constraintlayout.core.parser;
/* loaded from: classes.dex */
public class CLElement {
    private int line;
    protected CLContainer mContainer;
    private final char[] mContent;
    protected static int MAX_LINE = 80;
    protected static int BASE_INDENT = 2;
    protected long start = -1;
    protected long end = Long.MAX_VALUE;

    public CLElement(char[] content) {
        this.mContent = content;
    }

    public boolean notStarted() {
        return this.start == -1;
    }

    public void setLine(int line) {
        this.line = line;
    }

    public int getLine() {
        return this.line;
    }

    public void setStart(long start) {
        this.start = start;
    }

    public long getStart() {
        return this.start;
    }

    public long getEnd() {
        return this.end;
    }

    public void setEnd(long end) {
        if (this.end != Long.MAX_VALUE) {
            return;
        }
        this.end = end;
        if (CLParser.DEBUG) {
            System.out.println("closing " + hashCode() + " -> " + this);
        }
        if (this.mContainer != null) {
            this.mContainer.add(this);
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void addIndent(StringBuilder builder, int indent) {
        for (int i = 0; i < indent; i++) {
            builder.append(' ');
        }
    }

    public String toString() {
        if (this.start > this.end || this.end == Long.MAX_VALUE) {
            return getClass() + " (INVALID, " + this.start + "-" + this.end + ")";
        }
        String content = new String(this.mContent);
        return getStrClass() + " (" + this.start + " : " + this.end + ") <<" + content.substring((int) this.start, ((int) this.end) + 1) + ">>";
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public String getStrClass() {
        String myClass = getClass().toString();
        return myClass.substring(myClass.lastIndexOf(46) + 1);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public String getDebugName() {
        if (CLParser.DEBUG) {
            return getStrClass() + " -> ";
        }
        return "";
    }

    public String content() {
        String content = new String(this.mContent);
        if (this.end == Long.MAX_VALUE || this.end < this.start) {
            return content.substring((int) this.start, ((int) this.start) + 1);
        }
        return content.substring((int) this.start, ((int) this.end) + 1);
    }

    public boolean isDone() {
        return this.end != Long.MAX_VALUE;
    }

    public void setContainer(CLContainer element) {
        this.mContainer = element;
    }

    public CLElement getContainer() {
        return this.mContainer;
    }

    public boolean isStarted() {
        return this.start > -1;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public String toJSON() {
        return "";
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public String toFormattedJSON(int indent, int forceIndent) {
        return "";
    }

    public int getInt() {
        if (this instanceof CLNumber) {
            return ((CLNumber) this).getInt();
        }
        return 0;
    }

    public float getFloat() {
        if (this instanceof CLNumber) {
            return ((CLNumber) this).getFloat();
        }
        return Float.NaN;
    }
}
