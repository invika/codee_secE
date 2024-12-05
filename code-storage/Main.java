import java.util.Calendar;
import java.util.GregorianCalendar;

public class Main {

    public static void main(String[] args) {
        displayCurrentMonth();
    }

    public static void displayCurrentMonth() {
        // Get the current date
        Calendar calendar = new GregorianCalendar();

        // Get the current year and month
        int year = calendar.get(Calendar.YEAR);
        int month = calendar.get(Calendar.MONTH) + 1; // Month is 0-11, so add 1

        // Print the month header
        System.out.println("   " + getMonthName(month) + " " + year);
        System.out.println("Mo Tu We Th Fr Sa Su");

        // Calculate the first day of the month and how many days are in it
        calendar.set(Calendar.DAY_OF_MONTH, 1);
        int firstDayOfWeek = calendar.get(Calendar.DAY_OF_WEEK);
        int daysInMonth = calendar.getActualMaximum(Calendar.DAY_OF_MONTH);

        // Print leading spaces for the first week
        for (int i = 1; i < firstDayOfWeek; i++) {
            System.out.print("   "); // 3 spaces for each day
        }

        // Print the days of the month
        for (int day = 1; day <= daysInMonth; day++) {
            System.out.printf("%2d ", day);
            if ((firstDayOfWeek + day - 1) % 7 == 0) { // Move to the next line after Saturday
                System.out.println();
            }
        }
        System.out.println(); // Add a newline after the calendar
    }

    private static String getMonthName(int month) {
        String[] monthNames = {
            "January", "February", "March", "April", "May", "June",
            "July", "August", "September", "October", "November", "December"
        };
        return monthNames[month - 1]; // Adjust index
    }
}
