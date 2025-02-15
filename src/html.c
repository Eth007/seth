#include "config.h"
#include "utils.h"

const char html_template[] = "<html lang=\"en-US\"><head>\n" \
                             "<title>Scoring Report</title>\n" \
                             "<link href=\"https://fonts.googleapis.com/css2?family=Share+Tech+Mono&amp;display=swap\" rel=\"stylesheet\">\n" \
                             "<link href=\"style.css\" rel=\"stylesheet\">\n" \
                             "</head>\n" \
                             "<body>\n" \
                             "<h1>Scoring Report</h1>\n" \
                             "%s\n" \
                             "<p id=\"score\"><b>%d out of %d scored vulnerabilities found</b></p>" \
                             "<p id=\"score\"><b>%d out of %d points earned</b></p>";

void writeReport(struct desc** vulns, int nVulns) {
    int points = 0;
    FILE *report = fopen(REPORT_PATH, "w");

    char* desc_text = calloc(120, nVulns);
    char buf[120];
    for (int i=0; i<nVulns; i++) {
        snprintf(buf, 120, "<p>%s - %d pts</p>", (char*) &vulns[i]->text, vulns[i]->pts);
        strcat(desc_text, buf);
    }

    fprintf(report, html_template, desc_text, nVulns, NUM_VULNS, points, MAX_POINTS);
    free(desc_text);
}
