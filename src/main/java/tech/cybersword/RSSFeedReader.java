package tech.cybersword;

import java.net.URL;

import com.rometools.rome.feed.synd.SyndEntry;
import com.rometools.rome.feed.synd.SyndFeed;
import com.rometools.rome.io.SyndFeedInput;
import com.rometools.rome.io.XmlReader;

public class RSSFeedReader {
    public static void main(String[] args) throws Exception {
        URL feedUrl = new URL("https://www.zerodayinitiative.com/rss/published/2025/");
        SyndFeedInput input = new SyndFeedInput();
        SyndFeed feed = input.build(new XmlReader(feedUrl));

        System.out.println("Feed-Titel: " + feed.getTitle());

        for (SyndEntry entry : feed.getEntries()) {
            System.out.println("Titel: " + entry.getTitle());
            System.out.println("Link: " + entry.getLink());
            System.out.println("Beschreibung: " + entry.getDescription().getValue());
            System.out.println("-----");
        }
    }
}
