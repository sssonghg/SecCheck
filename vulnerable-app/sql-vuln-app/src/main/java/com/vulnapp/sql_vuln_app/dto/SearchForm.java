package com.vulnapp.sql_vuln_app.dto;

public class SearchForm {
    private String keyword;
    private int size = 10;

    public String getKeyword() { return keyword; }
    public void setKeyword(String keyword) { this.keyword = keyword; }
    public int getSize() { return size; }
    public void setSize(int size) { this.size = size; }
}