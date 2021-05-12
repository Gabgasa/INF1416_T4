package ternary_tree;

public class Node {
	private String fone;
	
	private int pos;
	private int left;
	private int mid;
	private int right;
	private int up;
	
	protected Node() {
		fone = new String("");
		
		pos = -1;
		left = -1;
		mid = -1;
		right = -1;
		up = -1;
	}
	
	protected Node(int p) {
		fone = new String("");
		setPos(p);
	}
	
	void setPos(int p)
	{
		pos = p;
		left = 3*pos + 1;
		mid = 3*pos + 2;
		right = 3*pos + 3; //case 0 cannot be 4*pos
		up = (pos -1)/3;
	}
	
	int getLeft()
	{
		return left;
	}

	int getMid()
	{
		return mid;
	}
	
	int getRight()
	{
		return right;
	}
	
	int getUp()
	{
		return up;
	}
	
	int getPos()
	{
		return pos;
	}
	
	void setFone(String str)
	{
		fone = str;
	}
	
	String getFone()
	{
		return fone;
	}
	
}
