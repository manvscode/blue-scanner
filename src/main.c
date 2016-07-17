/*
 * Copyright (C) 2016 by Joseph A. Marrero. http://www.manvscode.com/
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <libutility/utility.h>
#include <libutility/console.h>
#include <libcollections/vector.h>

#define VERSION "1.0"

static bool address_resolve( const char* hostname, int* protocol_family, struct sockaddr** address, socklen_t* address_length );
static bool port_scanning_task( int* percent, void* data );
static int known_port_compare( const void *l, const void *r);
static void signal_interrupt_handler( int dummy );
static void signal_quit_handler( int dummy );
static void about( int argc, char* argv[] );

typedef struct {
    unsigned short port;
    char recv_buffer[ 256 ];
} connection_info_t;

typedef struct known_port {
    unsigned short port;
    unsigned short type; // 1 for tcp;
    const char* desc;
} known_port_t;


static const known_port_t known_ports[] = {
    { .port = 1, .type = 1, .desc = "TCP Port Service Multiplexer (TCPMUX)" },
    { .port = 5, .type = 1, .desc = "Remote Job Entry (RJE)" },
    { .port = 7, .type = 1, .desc = "ECHO" },
    { .port = 18, .type = 1, .desc = "Message Send Protocol (MSP)" },
    { .port = 20, .type = 1, .desc = "FTP -- Data" },
    { .port = 21, .type = 1, .desc = "FTP -- Control" },
    { .port = 22, .type = 1, .desc = "SSH Remote Login Protocol" },
    { .port = 23, .type = 1, .desc = "Telnet" },
    { .port = 25, .type = 1, .desc = "Simple Mail Transfer Protocol (SMTP)" },
    { .port = 29, .type = 1, .desc = "MSG ICP" },
    { .port = 37, .type = 1, .desc = "Time" },
    { .port = 42, .type = 1, .desc = "Host Name Server (Nameserv)" },
    { .port = 43, .type = 1, .desc = "WhoIs" },
    { .port = 49, .type = 1, .desc = "Login Host Protocol (Login)" },
    { .port = 53, .type = 1, .desc = "Domain Name System (DNS)" },
    { .port = 69, .type = 1, .desc = "Trivial File Transfer Protocol (TFTP)" },
    { .port = 70, .type = 1, .desc = "Gopher Services" },
    { .port = 79, .type = 1, .desc = "Finger" },
    { .port = 80, .type = 1, .desc = "HTTP" },
    { .port = 103, .type = 1, .desc = "X.400 Standard" },
    { .port = 108, .type = 1, .desc = "SNA Gateway Access Server" },
    { .port = 109, .type = 1, .desc = "POP2" },
    { .port = 110, .type = 1, .desc = "POP3" },
    { .port = 115, .type = 1, .desc = "Simple File Transfer Protocol (SFTP)" },
    { .port = 118, .type = 1, .desc = "SQL Services" },
    { .port = 119, .type = 1, .desc = "Newsgroup (NNTP)" },
    { .port = 137, .type = 1, .desc = "NetBIOS Name Service" },
    { .port = 139, .type = 1, .desc = "NetBIOS Datagram Service" },
    { .port = 143, .type = 1, .desc = "Interim Mail Access Protocol (IMAP)" },
    { .port = 150, .type = 1, .desc = "NetBIOS Session Service" },
    { .port = 156, .type = 1, .desc = "SQL Server" },
    { .port = 161, .type = 1, .desc = "SNMP" },
    { .port = 179, .type = 1, .desc = "Border Gateway Protocol (BGP)" },
    { .port = 190, .type = 1, .desc = "Gateway Access Control Protocol (GACP)" },
    { .port = 194, .type = 1, .desc = "Internet Relay Chat (IRC)" },
    { .port = 197, .type = 1, .desc = "Directory Location Service (DLS)" },
    { .port = 389, .type = 1, .desc = "Lightweight Directory Access Protocol (LDAP)" },
    { .port = 396, .type = 1, .desc = "Novell Netware over IP" },
    { .port = 443, .type = 1, .desc = "HTTPS" },
    { .port = 444, .type = 1, .desc = "Simple Network Paging Protocol (SNPP)" },
    { .port = 445, .type = 1, .desc = "Microsoft-DS" },
    { .port = 458, .type = 1, .desc = "Apple QuickTime" },
    { .port = 546, .type = 1, .desc = "DHCP Client" },
    { .port = 547, .type = 1, .desc = "DHCP Server" },
    { .port = 563, .type = 1, .desc = "SNEWS" },
    { .port = 569, .type = 1, .desc = "MSN" },
    { .port = 1080, .type = 1, .desc = "Socks" }
};

static const size_t known_ports_size = sizeof(known_ports) / sizeof(known_ports[0]);

typedef struct {
    const char* hostname;
    int protocol_family;
    struct sockaddr* address;
    socklen_t address_length;
    unsigned short connection_to;
    unsigned short current_port;
    unsigned short first_port;
    unsigned short last_port;
    connection_info_t* connection_info;
} port_scanning_args_t;


int main( int argc, char* argv[] )
{
    signal( SIGINT, signal_interrupt_handler );
    signal( SIGQUIT, signal_quit_handler );

    port_scanning_args_t args = {
        .hostname        = NULL,
        .protocol_family = 0,
        .address         = NULL,
        .address_length  = 0,
        .connection_to   = 200,
        .first_port      = 1,
        .last_port       = 1024,
        .connection_info = NULL
    };

    if( argc < 2 )
    {
        about( argc, argv );
        return -1;
    }
    else
    {
        for( int arg = 1; arg < argc; arg++ )
        {
            if( strcmp( "-h", argv[arg] ) == 0 || strcmp( "--host", argv[arg] ) == 0 )
            {
                args.hostname = argv[ arg + 1 ];
                arg++;
            }
            else if( strcmp( "-fp", argv[arg] ) == 0 || strcmp( "--first-port", argv[arg] ) == 0 )
            {
                args.first_port = atoi(argv[ arg + 1 ] );
                arg++;
            }
            else if( strcmp( "-lp", argv[arg] ) == 0 || strcmp( "--last-port", argv[arg] ) == 0 )
            {
                args.last_port = atoi(argv[ arg + 1 ] );
                arg++;
            }
            else if( strcmp( "-t", argv[arg] ) == 0 || strcmp( "--timeout", argv[arg] ) == 0 )
            {
                args.connection_to = atoi(argv[ arg + 1 ]);
                arg++;
            }
            else
            {
                console_fg_color_256( stderr, CONSOLE_COLOR256_RED );
                printf( "\n" );
                fprintf( stderr, "ERROR: " );
                console_reset( stderr );
                fprintf( stderr, "Unrecognized command line option '%s'\n", argv[arg] );
                about( argc, argv );
                return -2;
            }
        }
    }

    if( args.hostname == NULL )
    {
        console_fg_color_256( stderr, CONSOLE_COLOR256_RED );
        fprintf( stderr, "ERROR: " );
        console_reset( stderr );
        fprintf( stderr, "Need at least the hostname to scan." );
        printf( "\n" );
        about( argc, argv );
        return -3;
    }



    args.current_port = args.first_port;

    vector_create( args.connection_info, args.last_port - args.first_port + 1 );

    console_fg_color_256( stdout, 0x19 );
    printf( " __________.__                     _________\n" );
    printf( " \\______   \\  |  __ __   ____     /   _____/ ____ _____    ____   ____   ___________ \n" );
    printf( "  |    |  _/  | |  |  \\_/ __ \\    \\_____  \\_/ ___\\\\__  \\  /    \\ /    \\_/ __ \\_  __ \\\n" );
    printf( "  |    |   \\  |_|  |  /\\  ___/    /        \\  \\___ / __ \\|   |  \\   |  \\  ___/|  | \\/\n" );
    printf( "  |______  /____/____/  \\___  >  /_______  /\\___  >____  /___|  /___|  /\\___  >__|\n" );
    printf( "         \\/                 \\/           \\/     \\/     \\/     \\/     \\/     \\/\n" );
    printf( "\n" );
    console_text_faderf( stdout, TEXT_FADER_BLUE_BEEP, "                                      Version %s", VERSION );
    printf( "\n" );
    console_text_fader( stdout, TEXT_FADER_BLUE_BEEP, "                                  Coded by Joe Marrero." );
    printf( "\n\n" );

    if( !address_resolve( args.hostname, &args.protocol_family, &args.address, &args.address_length ) )
    {
        console_fg_color_256( stderr, CONSOLE_COLOR256_RED );
        fprintf( stderr, "ERROR: " );
        console_reset( stderr );
        fprintf( stderr, "Unable to resolve address.\n");
    }
    else
    {
        char ip_string[ INET6_ADDRSTRLEN ];
        void* addr = (args.protocol_family == PF_INET6 ? (void*)&((struct sockaddr_in6*) args.address)->sin6_addr :
                                             (void*)&((struct sockaddr_in*) args.address)->sin_addr);
        if( !inet_ntop( args.protocol_family, addr, ip_string, sizeof(ip_string) ) )
        {
            console_fg_color_256( stderr, CONSOLE_COLOR256_RED );
            fprintf( stderr, "ERROR: " );
            console_reset( stderr );
            fprintf( stderr, "Unable to convert network address to string. %s.", strerror(errno) );
        }


        char task_desc[ 128 ];
        snprintf( task_desc, sizeof(task_desc), "Scanning %d to %d on %s (%s)...", args.first_port, args.last_port, args.hostname, ip_string );
        task_desc[ sizeof(task_desc) - 1 ] = '\0';
        console_text_fader( stdout, TEXT_FADER_BLUE_BEEP, task_desc );
        printf( "\n" );
        printf( "\n" );
        console_progress_indicator( stdout, "", PROGRESS_INDICATOR_STYLE_BLUE, port_scanning_task, &args );

        free( args.address );
    }

    printf( "\n" );

    console_text_faderf( stdout, TEXT_FADER_BLUE_BEEP, "Found %d ports open.", vector_size(args.connection_info) ); printf( "\n\n" );


    console_text_fader( stdout, TEXT_FADER_BLUE_BEEP, "PORT     DESC" ); printf( "\n" );
    console_text_fader( stdout, TEXT_FADER_BLUE_BEEP, "-----    ---------" ); printf( "\n" );

    for( int i = 0; i < vector_size(args.connection_info); i++ )
    {
        connection_info_t* info = &args.connection_info[ i ];

        known_port_t* known_port = bsearch( &info->port, known_ports, known_ports_size, sizeof(known_port_t), known_port_compare );

        console_text_faderf( stdout, TEXT_FADER_BLUE_BEEP, "%-5d    %s",  info->port, known_port ? known_port->desc : "unknown" );
        printf( "\n" );
    }

    vector_destroy( args.connection_info );
    printf( "\n" );

    return 0;
}

bool address_resolve( const char* hostname, int* protocol_family, struct sockaddr** address, socklen_t* address_length )
{
    bool result = false;
    struct addrinfo* gai_result = NULL;

    struct addrinfo hints = { 0 };
    //memset( &hints, 0, sizeof(hints) );
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int gai_status = getaddrinfo( hostname, NULL, &hints, &gai_result );

    if( gai_status != 0 )
    {
        #if 0
        console_fg_color_256( stderr, CONSOLE_COLOR256_RED );
        fprintf( stderr, "ERROR: " );
        console_reset( stderr );
        fprintf( stderr, "%s.", gai_strerror(gai_status) );
        #endif
        goto done;
    }

    const struct sockaddr* addr = NULL;
    int addr_pf = 0;
    socklen_t addr_len = 0;
    bool found_ipv6 = false;

    for( const struct addrinfo* p = gai_result;
         !found_ipv6 && p != NULL;
         p = p->ai_next )
    {
        if( p->ai_family == PF_INET6 )
        {
            addr_pf  = p->ai_family;
            addr     = p->ai_addr;
            addr_len = p->ai_addrlen;

            found_ipv6 = true;
        }
        else if( p->ai_family == PF_INET )
        {
            addr_pf  = p->ai_family;
            addr     = p->ai_addr;
            addr_len = p->ai_addrlen;
        }
    }

    if( addr )
    {
        *address = malloc( addr_len );

        if( *address )
        {
            *protocol_family = addr_pf;
            *address_length  = addr_len;

            memcpy( *address, addr, addr_len );
            result = true;
        }
    }

done:
    if( gai_result )
    {
        //freeaddrinfo( gai_result );
    }

    return result;
}


bool port_scanning_task( int* percent, void* data )
{
    bool port_scanned = true;
    port_scanning_args_t* args = (port_scanning_args_t*) data;

    int sock = socket( args->protocol_family, SOCK_STREAM, 0 );

    if( sock < 0 )
    {
        console_fg_color_256( stderr, CONSOLE_COLOR256_RED );
        printf( "\n" );
        fprintf( stderr, "ERROR: " );
        console_reset( stderr );
        fprintf( stderr, "Unable to create socket. %s.", strerror(errno) );
        port_scanned = false;
        goto done;
    }

    int so_reuse_addr = 1;
    if( setsockopt( sock, SOL_SOCKET, SO_REUSEADDR, &so_reuse_addr, sizeof(so_reuse_addr) ) < 0 )
    {
        console_fg_color_256( stderr, CONSOLE_COLOR256_RED );
        printf( "\n" );
        fprintf( stderr, "ERROR: " );
        console_reset( stderr );
        fprintf( stderr, "Unable to set address reuse. %s.", strerror(errno) );
        port_scanned = false;
        goto done;
    }

    int so_reuse_port = 1;
    if( setsockopt( sock, SOL_SOCKET, SO_REUSEPORT, &so_reuse_port, sizeof(so_reuse_port) ) < 0 )
    {
        console_fg_color_256( stderr, CONSOLE_COLOR256_RED );
        printf( "\n" );
        fprintf( stderr, "ERROR: " );
        console_reset( stderr );
        fprintf( stderr, "Unable to set port reuse. %s.", strerror(errno) );
        port_scanned = false;
        goto done;
    }

#if 0
    struct timeval so_receive_timeout = {
        .tv_sec = 0,
        .tv_usec = 1000 * 100,
    };
    if( setsockopt( sock, SOL_SOCKET, SO_RCVTIMEO, &so_receive_timeout, sizeof(so_receive_timeout) ) < 0 )
    {
        console_fg_color_256( stderr, CONSOLE_COLOR256_RED );
        printf( "\n" );
        fprintf( stderr, "ERROR: " );
        console_reset( stderr );
        fprintf( stderr, "Unable to set receive timeout. %s.", strerror(errno) );
        port_scanned = false;
        goto done;
    }

    struct timeval so_send_timeout = {
        .tv_sec = 0,
        .tv_usec = 1000 * 100,
    };
    if( setsockopt( sock, SOL_SOCKET, SO_SNDTIMEO, &so_send_timeout, sizeof(so_send_timeout) ) < 0 )
    {
        console_fg_color_256( stderr, CONSOLE_COLOR256_RED );
        printf( "\n" );
        fprintf( stderr, "ERROR: " );
        console_reset( stderr );
        fprintf( stderr, "Unable to set send timeout. %s.", strerror(errno) );
        port_scanned = false;
        goto done;
    }
#endif

    if( args->protocol_family == PF_INET6 )
    {
        struct sockaddr_in6* addr_in = (struct sockaddr_in6*) args->address;
        addr_in->sin6_port = htons(args->current_port);
    }
    else
    {
        struct sockaddr_in* addr_in = (struct sockaddr_in*) args->address;
        addr_in->sin_port = htons(args->current_port);
    }

    fcntl( sock, F_SETFL, O_NONBLOCK );

    if( connect( sock, args->address, args->address_length ) < 0 )
    {
        if( errno != EINPROGRESS )
        {
            console_fg_color_256( stderr, CONSOLE_COLOR256_RED );
            printf( "\n" );
            fprintf( stderr, "ERROR: " );
            console_reset( stderr );
            fprintf( stderr, "Unable to connect to %s:%d. %s (%d).\n", args->hostname, args->current_port, strerror(errno), errno );
            port_scanned = false;
            goto done;
        }
    }

    fd_set fdset;
    FD_ZERO( &fdset );
    FD_SET( sock, &fdset );

    struct timeval connection_timeout = {
        .tv_sec  = 0,
        .tv_usec = 1000 * args->connection_to
    };

    if( select(sock + 1, NULL, &fdset, NULL, &connection_timeout) == 1 )
    {
        int so_error = 0;
        socklen_t so_error_len = sizeof(so_error);

        getsockopt( sock, SOL_SOCKET, SO_ERROR, &so_error, &so_error_len );

        if( so_error == 0 )
        {
            // TODO: Connection successful.
            fcntl( sock, F_SETFL, ~O_NONBLOCK );

            connection_info_t info = {
                .port = args->current_port,
            };

            recv( sock, info.recv_buffer, sizeof(info.recv_buffer) - 1, 0 );
            info.recv_buffer[ sizeof(info.recv_buffer) - 1 ] = '\0';

            vector_push( args->connection_info, info );
        }
    }

done:
    if( sock >= 0 )
    {
        close( sock );
    }

    *percent = (args->current_port - args->first_port) * 100 / (args->last_port - args->first_port);

    args->current_port += 1;
    return port_scanned;
}

int known_port_compare( const void *l, const void *r)
{
    const known_port_t* left  = l;
    const known_port_t* right = r;

    return left->port - right->port;
}

void signal_interrupt_handler( int dummy )
{
    printf( "\n" );
    console_text_fader( stdout, TEXT_FADER_BLUE_BEEP, "Scan canceled." );
    printf( "\n" );
    console_reset( stdout );
    exit( EXIT_SUCCESS );
}

void signal_quit_handler( int dummy )
{
    printf( "\n" );
    console_text_fader( stdout, TEXT_FADER_BLUE_BEEP, "Scan canceled." );
    printf( "\n" );
    console_reset( stdout );
    exit( EXIT_SUCCESS );
}

void about( int argc, char* argv[] )
{
    console_text_faderf( stdout, TEXT_FADER_BLUE_BEEP, "Blue Scanner v%s", VERSION );
    printf( "\n" );
    console_text_faderf( stdout, TEXT_FADER_BLUE_BEEP, "Copyright (c) 2016, Joe Marrero.");
    printf( "\n\n" );

    console_text_faderf( stdout, TEXT_FADER_BLUE_BEEP, "Usage:" );
    printf( "\n" );
    console_text_faderf( stdout, TEXT_FADER_BLUE_BEEP, "    %s -h <hostname> [-fp <first-port> -lp <last-port> -t <connection-timeout>]", argv[0] );
    printf( "\n\n" );

    console_text_faderf( stdout, TEXT_FADER_BLUE_BEEP, "Command Line Options:" );
    printf( "\n" );
    console_text_faderf( stdout, TEXT_FADER_BLUE_BEEP, "    %-2s, %-12s  %-50s", "-h", "--hostname", "The host to scan." );
    printf( "\n" );
    console_text_faderf( stdout, TEXT_FADER_BLUE_BEEP, "    %-2s, %-12s  %-50s", "-fp", "--first-port", "Start scanning from this port. Default is 1" );
    printf( "\n" );
    console_text_faderf( stdout, TEXT_FADER_BLUE_BEEP, "    %-2s, %-12s  %-50s", "-lp", "--last-port", "The last port to scan. Default is 1024." );
    printf( "\n" );
    console_text_faderf( stdout, TEXT_FADER_BLUE_BEEP, "    %-2s, %-12s  %-50s", "-t", "--timeout", "Sets the connection timeout." );
    printf( "\n\n" );
}
