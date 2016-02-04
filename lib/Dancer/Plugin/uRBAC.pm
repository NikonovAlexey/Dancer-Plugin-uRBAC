package Dancer::Plugin::uRBAC;
# ABSTRACT: Плагин взаимодействия с ролями для Dancer.

use strict;
use warnings;

use Dancer ':syntax';
use Dancer::Plugin;
use Dancer::Plugin::DBIC;
use Dancer::Plugin::FlashNote;

use FAW::uRoles;
use Data::Dump qw(dump);
use FindBin qw($Bin);
use Try::Tiny;
use POSIX 'strftime';
use Digest::MD5 qw(md5_hex);

my $conf = plugin_setting;

# просолить пароль по стандарту

sub salt_pass {
    my $upass   = shift;
    my $salt    = shift;
   
    if ( ! defined( $upass ) || ! defined( $salt ) ) {
        return "-1";
    }
    
    # выкинуть нафиг все не-латинские символы
    $upass =~ /([A-Za-z0-9]*)/; $upass = $1 || "";
    $salt =~ /([A-Za-z0-9]*)/; $salt = $1 || "";
    $upass = md5_hex(md5_hex($upass) . $salt);
    
    return $upass;
};

sub halt_session {
    session user => {
        id      => "",
        login => "",
        roles => "guest",
        email => "",
        fullname => "guest",
    };
};

=encoding utf-8

=cut

=head1 NAME

Dancer::Plugin::uRBAC - micro Role Based Access Control

=head1 VERSION

0.2

=head1 SYNOPSIS

Опишите конфигурацию доступа к различным точкам.

    config.yml:
        ...
        plugins:
            uRBAC:
            roles:
                /: any
                /page/:url: any
                /page/:url/edit: admin
        ...

Подключите модуль:

    use Dancer::Plugin::uRBAC;

В общем шаблоне выполняйте проверку прав доступа и отрисовку странички запрещения
(для TemplateToolkit):

    [% IF deny_flag != 0; INCLUDE $deny_template; ELSE; content; END %]

В теле основного проекта можно использовать проверку ролей...

    get '/' => sub {
        ...
        if (rights('admin') {
            warning " ::::::::::::::::: your are is admin' rights";
        } else {
            warning " ::::::::::::::::: your are isn't admin";
        }
        ...
    }

... и модификацию прав доступа согласно иной логики:

    get '/page/:url' => sub {
        ...

        if ( foo ) {
            access_deny;
        } else {
            access_grant;
        }

    }

В шаблоне возможно проверять права текущего пользователя следующим образом:

    [% IF rights(admin) %]<a href="modify">изменить содержимое</a>[% END %]

=cut 

=head1 DESCRIPTION

Плагин, добавляющий в Dancer функционал контроля на основе ролей.

При подключении модуля устанавливается два хука: перед вызовом и при отрисовке
шаблона. Кроме того, управлять поведением запрещения можно с помощью
экспортируемых процедур.

При работе модуля используются следующие внешние точки и соглашения:

- session->{user}->{roles} хранит список ролей текущего пользователя;

- если роль не определена, она считается гостевой (guest);

- шаблон запрещения находится в views/components/defdeny.tt;

- шаблон запрещения можно переопределить опцией deny_template в конфиге модуля; 

- проверять права можно прямо в шаблонизаторе, для этого в него передаётся
ссылка на процедуру rights;

=cut

=head2 rights

Сердце модуля - процедура проверки прав доступа. На входе нужно указать список ролей,
а на выходе возвращается 1, если роль текущего пользователя совпадёт с одной из указанных ролей
или undef, если роль текущего пользователя в списке ролей не будет найдена

=cut

sub rights {
    my $input_method = lc(request->{method})     || "";
    my $current_role = session->{user}->{roles}  || "guest";
    my $flag = undef;
    
    warning " =========== try to debug role!!! ";
    foreach my $rolelist ( @_ ) {
        $flag = 1 if ( FAW::uRoles->check_role(
            $current_role, $input_method, $rolelist ) == 0 );
    };
    
    return $flag; 
}

=head2 say_if_debug

Сказанную на входе фразу выведем на консоль только при взведённом флаге отладки.

=cut

sub say_if_debug {
    my $debug = config->{plugins}->{uRBAC}->{debug} || 0;
    if ( $debug == 1 ) { warning $_[0]; }
}

=head2 history

Запись истории посещения в лог. Если указан комментарий, то пишем историю не в
лог, а в таблицу БД.

=cut

sub history {
    my $uid = session->{user}->{id} || "guest";
    my $timestamp = strftime('%Y.%m.%d %H:%M:%S', localtime(time));
    my $action = request->{env}->{'PATH_INFO'};
    my $method = request->{env}->{'REQUEST_METHOD'};
    my $addr = request->{env}->{'REMOTE_ADDR'} || "127.0.0.1";
    my $agent = request->{headers}->{'user-agent'};
    my $notes = join(',', @_);
    
    if ( $notes ) {
        schema->resultset('History')->create({
            userid => $uid,
            method => $method,
            action => $action,
            address=> $addr,
            agent  => $agent,
            notes  => $notes,
        });
    } else {
        say_if_debug(" [$timestamp] uid #$uid $method $action from $addr");
    };
}

=head2 хук before 

Основной механизм установки прав на основе конфигурации и правил. 

Перед вызовом логики работы каждой точки мы инициируем базовые переменные. На
основе внешнего модуля FAW::uRoles и конфигурации config.yaml мы выполняем проверки 
прав доступа текущего пользователя к текущей точке и устанавливаем флаг доступа.
    

=cut

hook 'before' => sub {
    my $current_role  = session->{user}->{roles}  || "guest";
    my $query_method  = lc(request->{method})     || "get";
    my $route_pattern = request->{_route_pattern} || '/';
    
    my $strong_secure       = $conf->{strong_secure} || 0;
    my $session_timeout     = $conf->{session_timeout} || 600;
    my $session_lifetime    = session->{lifetime}    || time + $session_timeout;
    my $long_session_flag   = session->{longsession} || 0;
    
    my $timestamp   = strftime('%Y.%m.%d %H:%M:%S', localtime(time));
    my $action      = request->{'path_info'};
    my $redirect;
    
    my $route_profile  = $conf->{roles}->{$route_pattern} || "";
    $conf->{deny_flag} = $conf->{deny_defaults} || 1;
    
    history();
    
    # Проверим текущую роль в сессии. Если она не определена, то сбросить
    # сессию на дефолт.
    if ( ! defined(session->{user}->{roles}) || (session->{user}->{roles} =~ /^\s*$/ ) ) {
        halt_session;
    }
    
    # Проверим указание "любой" роли для обхода детальной проверки.
    if ($route_profile =~ /any|all/i ) { 
        say_if_debug(sprintf qq( [%s] GRANT for any user at %s),
            $timestamp, $route_pattern 
        );
        return $conf->{deny_flag} = 0; 
    };
    
    # TODO: в некоторых случаях возвращается некорректный код. Следует отладить
    # проверку прав и прикрутить корректное значение обработки проверки прав.
    $conf->{deny_flag} = FAW::uRoles->check_role($current_role, $query_method, $route_profile);
    
    say_if_debug(sprintf qq( [%s] %s role '%s' at %s),
        $timestamp, ( $conf->{deny_flag} > 0 ) ? "DENY or WRONG rights" : "GRANT",
        $current_role, $route_pattern
    );
    
    # Заблокируем доступ к содержимому и перенаправим к определённому разделу
    if ( ( $strong_secure ) && ( $conf->{deny_flag} > 0 ) ) {
        $redirect     = config->{plugins}->{uRBAC}->{deny_page} || "/deny";
        warning "Try to lock action for user: strong secure is enabled; redirect to $redirect page";
        redirect($redirect . "?redir=" . $action);
        return;
    };
    
    # Проверим время жизни нашей сессии и выкинем пользователя, если оно было исчерпано
    if ( $current_role ne "guest" ) {
        if ( $long_session_flag eq "1" ) {
            warning "don't modify session time - long session";
        } elsif ( $session_lifetime > time ) {
            session lifetime => time + $session_timeout;
        } else {
            warning "session timeout";
            flash "Вы слишком долго не выполняли никаких действий, поэтому <strong>в целях
            безопасности</strong> система произвела автоматическое завершение сеанса. Но Вы
            можете в любой момент повторно зайти в систему.";
            halt_session;
            redirect($redirect . "?redir=" . $action);
        }
    } else {
        halt_session;
    }
};

=head2 хук before_template_render

Для корректной работы с правами в шаблонизаторе мы должны передать туда
текущее состояние флага запрещения, адрес шаблона с текстом запрещения и ссылку
на процедуру прав доступа.

=cut

hook 'before_template_render' => sub {
    my ($values) = @_;
    $values->{deny_flag}        = $conf->{deny_flag};
    $values->{deny_template}    = $conf->{deny_template} || 'components/defdeny.tt';
    $values->{rights}           = \&rights;
};

=head2 rights

Проверить права доступа текущего пользователя к текущему контенту можно 
и прямо в процедуре контента, для этого регистрируется ключевое слово rights.

На входе следует передать название роли, на которую следует проверить
текущего пользователя.

    my $currights = rights('admin');

Проверка не меняет текущий статус. Для этого следует использовать другие
процедуры.

=cut 

register rights         => \&rights;
register history        => \&history;
register salt_pass      => \&salt_pass;

=head2 access_status

Запросить текущий статус (возвращает текущий статус: 1 = блокируется, 0 =
доступно).

=head2 access_deny

Назначить статус "доступ заблокирован".

=head2 access_grant

Назначить статус "доступ разрешён".

=cut

register access_status  => sub { return $conf->{deny_flag}; };
register access_deny    => sub { $conf->{deny_flag} = 1; };
register access_grant   => sub { $conf->{deny_flag} = 0; };

register_plugin;

1;
