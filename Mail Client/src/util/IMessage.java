package util;


public interface IMessage {
	public final static char DEMILITER = ' ';
	
	public String craftToString();
	public void parse(String str);
}
